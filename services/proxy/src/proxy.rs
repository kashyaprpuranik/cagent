//! HTTP forward proxy handler.
//!
//! Accepts plain HTTP requests (non-CONNECT), checks domain allowlist,
//! injects credentials, and forwards upstream.

use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, StatusCode};

use crate::config::{parse_timeout, CONFIG};
use crate::util::{
    access_log_now, error_response, instrument_response_body, is_hop_by_hop, AccessLogContext,
    ProxyResponse, MAX_BODY_BYTES, UPSTREAM_CLIENT,
};

/// Blocked metadata IPs (cloud credential theft prevention).
const METADATA_IPS: &[&str] = &["169.254.169.254", "metadata.google.internal"];

/// Build an access log context for an early-exit (block, error, timeout) path.
fn ctx(
    domain: &str,
    method: &hyper::Method,
    path: &str,
    response_code: u16,
    start: std::time::Instant,
    bytes_received: usize,
    credential_injected: bool,
) -> AccessLogContext {
    AccessLogContext {
        domain: domain.to_string(),
        method: method.clone(),
        path: path.to_string(),
        response_code,
        start,
        bytes_received,
        credential_injected,
    }
}

/// Handle an incoming HTTP proxy request.
///
/// 1. Extract the target host from the request.
/// 2. Check domain allowlist.
/// 3. Check path filtering (if configured).
/// 4. Check read-only enforcement (block POST/PUT/DELETE if read_only).
/// 5. Inject credentials (if configured for this domain).
/// 6. Forward to upstream (response body streams back to the cell).
pub async fn handle_request(
    req: Request<Incoming>,
) -> Result<ProxyResponse, hyper::Error> {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path_and_query().map(|pq| pq.to_string()).unwrap_or_else(|| "/".to_string());

    // Extract host from the request (Host header or URI authority)
    let host = extract_host(&req).unwrap_or_default();

    if host.is_empty() {
        return Ok(error_response(StatusCode::BAD_REQUEST, "Missing host"));
    }

    // Strip port from host for domain matching
    let domain = host.split(':').next().unwrap_or(&host);

    // Block cloud metadata endpoint (defense-in-depth)
    if METADATA_IPS.iter().any(|ip| domain.eq_ignore_ascii_case(ip)) {
        access_log_now(ctx(domain, &method, &path, 403, start, 0, false));
        return Ok(error_response(StatusCode::FORBIDDEN, "Metadata endpoint blocked"));
    }

    // Load current config (lock-free)
    let config = CONFIG.load();

    // 1. Domain allowlist check
    if !config.is_allowed(domain) {
        access_log_now(ctx(domain, &method, &path, 403, start, 0, false));
        return Ok(error_response(StatusCode::FORBIDDEN, "Domain not allowed"));
    }

    // Resolve devbox.local alias → real domain
    let real_domain: String;
    let is_alias;
    if let Some(policy) = config.resolve_alias(domain) {
        real_domain = policy.domain.clone();
        is_alias = true;
        tracing::debug!(alias = domain, domain = %real_domain, "alias resolved");
    } else {
        real_domain = domain.to_string();
        is_alias = false;
    }

    // Get domain policy for additional checks (use real domain)
    let policy = config.get_policy(domain);

    // 2. Read-only enforcement
    if let Some(p) = policy {
        if p.read_only && !matches!(method, hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS) {
            access_log_now(ctx(&real_domain, &method, &path, 403, start, 0, false));
            return Ok(error_response(StatusCode::FORBIDDEN, "Write methods not allowed for this domain"));
        }
    }

    // 3. Path filtering
    if let Some(p) = policy {
        if !p.allowed_paths.is_empty() {
            let req_path = uri.path();
            let path_allowed = p.allowed_paths.iter().any(|pattern| {
                if pattern.ends_with('*') {
                    req_path.starts_with(pattern.trim_end_matches('*'))
                } else {
                    req_path == pattern
                }
            });
            if !path_allowed {
                access_log_now(ctx(&real_domain, &method, &path, 403, start, 0, false));
                return Ok(error_response(StatusCode::FORBIDDEN, "Path not allowed"));
            }
        }
    }

    // 4. Rate limiting
    if let Some(p) = policy {
        if let Some(rpm) = p.rate_limit_rpm {
            if !crate::config::check_rate_limit(&real_domain, rpm, p.burst_size) {
                access_log_now(ctx(&real_domain, &method, &path, 429, start, 0, false));
                return Ok(error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
            }
        }
    }

    // 5. Build upstream request — pick scheme from per-domain `tls` flag.
    // tls defaults to true (HTTPS upstream); explicit `tls: false` keeps HTTP.
    let upstream_host = if is_alias { &real_domain } else { &host };
    let use_tls = policy.map(|p| p.tls).unwrap_or(true);
    let scheme = if use_tls { "https" } else { "http" };
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let upstream_uri = format!("{}://{}{}", scheme, upstream_host, path_and_query);

    let mut upstream_req = Request::builder()
        .method(method.clone())
        .uri(&upstream_uri);

    // Copy headers, skipping hop-by-hop and Host (we'll set it explicitly for aliases)
    for (name, value) in req.headers() {
        if !is_hop_by_hop(name.as_str()) && !(is_alias && name == hyper::header::HOST) {
            upstream_req = upstream_req.header(name, value);
        }
    }

    // Rewrite Host header for aliases
    if is_alias {
        upstream_req = upstream_req.header("Host", real_domain.as_str());
    }

    // Add X-Real-Domain header (for upstream logging/routing)
    upstream_req = upstream_req.header("X-Real-Domain", real_domain.as_str());

    // 6. Credential injection
    let mut credential_injected = false;
    if let Some(p) = policy {
        if let (Some(header), Some(format), Some(value)) =
            (&p.credential_header, &p.credential_format, &p.credential_value)
        {
            let header_value = format.replace("{value}", value);
            upstream_req = upstream_req.header(header.as_str(), header_value);
            upstream_req = upstream_req.header("X-Credential-Injected", "true");
            credential_injected = true;
            tracing::debug!(domain = domain, header = header.as_str(), "credential injected");
        }
    }

    // Collect request body (with size limit to prevent OOM).  DLP scanning
    // needs the full body, so request side is not streamed.
    let content_length: usize = req.headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        access_log_now(ctx(&real_domain, &method, &path, 413, start, 0, credential_injected));
        return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large"));
    }
    let body_bytes = req.collect().await?.to_bytes();
    let bytes_received = body_bytes.len();
    if bytes_received > MAX_BODY_BYTES {
        access_log_now(ctx(&real_domain, &method, &path, 413, start, bytes_received, credential_injected));
        return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large"));
    }

    // DLP scanning — every action emits a structured dlp_violation event so
    // Vector → VictoriaLogs → analytics widgets show the detection.
    let body_to_send = match crate::dlp::scan_body(&body_bytes, &real_domain) {
        crate::dlp::DlpAction::Allow => body_bytes,
        crate::dlp::DlpAction::Log(findings) => {
            crate::dlp::emit_violation(method.as_str(), &real_domain, &path, &findings);
            body_bytes
        }
        crate::dlp::DlpAction::Block(findings) => {
            crate::dlp::emit_violation(method.as_str(), &real_domain, &path, &findings);
            access_log_now(ctx(&real_domain, &method, &path, 403, start, bytes_received, credential_injected));
            return Ok(error_response(StatusCode::FORBIDDEN, "Blocked by DLP: request body contains sensitive data"));
        }
        crate::dlp::DlpAction::Redact(findings, redacted) => {
            crate::dlp::emit_violation(method.as_str(), &real_domain, &path, &findings);
            redacted.into()
        }
    };

    let upstream_req = upstream_req
        .body(Full::new(body_to_send))
        .unwrap();

    // 7. Forward upstream (with per-domain timeout from policy).  Timeout
    // applies until response headers arrive — once we have headers we hand
    // the streaming body off to the client without further deadline
    // (matches Envoy's `route.timeout` semantics).
    let upstream_timeout = parse_timeout(policy.and_then(|p| p.timeout.as_deref()));
    match tokio::time::timeout(upstream_timeout, UPSTREAM_CLIENT.request(upstream_req)).await {
        Err(_) => {
            access_log_now(ctx(&real_domain, &method, &path, 504, start, bytes_received, credential_injected));
            Ok(error_response(StatusCode::GATEWAY_TIMEOUT, "Upstream request timed out"))
        }
        Ok(Ok(resp)) => {
            let (parts, body) = resp.into_parts();
            let status = parts.status.as_u16();
            // Build the streaming response: copy non-hop-by-hop headers and
            // wrap the upstream body so the access log fires (with bytes_sent)
            // when the body finishes streaming or is dropped.
            let mut builder = hyper::Response::builder().status(parts.status);
            for (name, value) in &parts.headers {
                if !is_hop_by_hop(name.as_str()) {
                    builder = builder.header(name, value);
                }
            }
            let log_ctx = ctx(&real_domain, &method, &path, status, start, bytes_received, credential_injected);
            let streamed = instrument_response_body(body, log_ctx);
            Ok(builder.body(streamed).unwrap())
        }
        Ok(Err(e)) => {
            tracing::error!(domain = %real_domain, error = %e, "upstream error");
            access_log_now(ctx(&real_domain, &method, &path, 502, start, bytes_received, credential_injected));
            Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream connection failed"))
        }
    }
}

/// Extract the host from a request (Host header or URI authority).
fn extract_host(req: &Request<Incoming>) -> Option<String> {
    // Try URI authority first (for absolute-form proxy requests)
    if let Some(authority) = req.uri().authority() {
        return Some(authority.to_string());
    }
    // Fall back to Host header
    req.headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
