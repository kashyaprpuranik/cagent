//! HTTP forward proxy handler.
//!
//! Accepts plain HTTP requests (non-CONNECT), checks domain allowlist,
//! injects credentials, and forwards upstream.

use std::sync::LazyLock;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::config::CONFIG;
use crate::util::{self, error_response, is_hop_by_hop, MAX_BODY_BYTES};

/// Shared HTTP client for connection pooling to upstream servers.
static HTTP_CLIENT: LazyLock<Client<HttpConnector, Full<Bytes>>> = LazyLock::new(|| {
    Client::builder(TokioExecutor::new()).build_http()
});

/// Blocked metadata IPs (cloud credential theft prevention).
const METADATA_IPS: &[&str] = &["169.254.169.254", "metadata.google.internal"];

/// Handle an incoming HTTP proxy request.
///
/// 1. Extract the target host from the request.
/// 2. Check domain allowlist.
/// 3. Check path filtering (if configured).
/// 4. Check read-only enforcement (block POST/PUT/DELETE if read_only).
/// 5. Inject credentials (if configured for this domain).
/// 6. Forward to upstream.
pub async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
        access_log(domain, &method, &path, 403, start, 0, 0, false);
        return Ok(error_response(StatusCode::FORBIDDEN, "Metadata endpoint blocked"));
    }

    // Load current config (lock-free)
    let config = CONFIG.load();

    // 1. Domain allowlist check
    if !config.is_allowed(domain) {
        access_log(domain, &method, &path, 403, start, 0, 0, false);
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
            access_log(&real_domain, &method, &path, 403, start, 0, 0, false);
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
                access_log(&real_domain, &method, &path, 403, start, 0, 0, false);
                return Ok(error_response(StatusCode::FORBIDDEN, "Path not allowed"));
            }
        }
    }

    // 4. Rate limiting
    if let Some(p) = policy {
        if let Some(rpm) = p.rate_limit_rpm {
            if !crate::config::check_rate_limit(&real_domain, rpm) {
                access_log(&real_domain, &method, &path, 429, start, 0, 0, false);
                return Ok(error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
            }
        }
    }

    // 5. Build upstream request
    let upstream_host = if is_alias { &real_domain } else { &host };
    let upstream_uri = if uri.scheme().is_some() && !is_alias {
        uri.to_string()
    } else {
        format!("http://{}{}", upstream_host, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
    };

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

    // Collect request body (with size limit to prevent OOM)
    let content_length: usize = req.headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        access_log(&real_domain, &method, &path, 413, start, 0, 0, credential_injected);
        return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large"));
    }
    let body_bytes = req.collect().await?.to_bytes();
    let bytes_received = body_bytes.len();
    if bytes_received > MAX_BODY_BYTES {
        access_log(&real_domain, &method, &path, 413, start, 0, bytes_received, credential_injected);
        return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large"));
    }

    // DLP scanning
    let body_to_send = match crate::dlp::scan_body(&body_bytes, &real_domain) {
        crate::dlp::DlpAction::Allow => body_bytes,
        crate::dlp::DlpAction::Log(findings) => {
            for f in &findings {
                tracing::warn!(domain = %real_domain, pattern = %f.pattern, snippet = %f.snippet, "DLP: sensitive data detected");
            }
            body_bytes
        }
        crate::dlp::DlpAction::Block(findings) => {
            for f in &findings {
                tracing::warn!(domain = %real_domain, pattern = %f.pattern, snippet = %f.snippet, "DLP: blocked");
            }
            access_log(&real_domain, &method, &path, 403, start, 0, bytes_received, credential_injected);
            return Ok(error_response(StatusCode::FORBIDDEN, "Blocked by DLP: request body contains sensitive data"));
        }
        crate::dlp::DlpAction::Redact(findings, redacted) => {
            for f in &findings {
                tracing::warn!(domain = %real_domain, pattern = %f.pattern, snippet = %f.snippet, "DLP: redacted");
            }
            redacted.into()
        }
    };

    let upstream_req = upstream_req
        .body(Full::new(body_to_send))
        .unwrap();

    // 7. Forward upstream (with timeout)
    match tokio::time::timeout(std::time::Duration::from_secs(30), forward_upstream(upstream_req)).await {
        Err(_) => {
            access_log(&real_domain, &method, &path, 504, start, 0, bytes_received, credential_injected);
            Ok(error_response(StatusCode::GATEWAY_TIMEOUT, "Upstream request timed out"))
        }
        Ok(result) => match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                access_log(&real_domain, &method, &path, status, start, 0, bytes_received, credential_injected);
                Ok(resp)
            }
            Err(e) => {
                tracing::error!(domain = %real_domain, error = %e, "upstream error");
                access_log(&real_domain, &method, &path, 502, start, 0, bytes_received, credential_injected);
                Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream connection failed"))
            }
        }
    }
}

/// Emit a structured access log entry with all fields the analytics pipeline
/// expects.  Vector's `parse_docker` transform parses the JSON and extracts
/// these fields; the `source:envoy AND log_type:access` filter in widget
/// queries matches because Vector classifies cagent-proxy logs with
/// `source = "envoy"` and sets `log_type = "access"` when `method` is present.
fn access_log(
    domain: &str,
    method: &hyper::Method,
    path: &str,
    response_code: u16,
    start: std::time::Instant,
    bytes_sent: usize,
    bytes_received: usize,
    credential_injected: bool,
) {
    let duration = start.elapsed().as_millis() as u64;
    tracing::info!(
        method = %method,
        path = path,
        authority = domain,
        upstream_host = domain,
        response_code = response_code,
        duration = duration,
        bytes_sent = bytes_sent,
        bytes_received = bytes_received,
        credential_injected = credential_injected,
        "access"
    );
}

/// Forward request to the upstream server.
async fn forward_upstream(
    req: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = HTTP_CLIENT.request(req).await?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();

    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if !is_hop_by_hop(name.as_str()) {
            response = response.header(name, value);
        }
    }

    Ok(response.body(Full::new(body)).unwrap())
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

