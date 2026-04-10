//! MITM HTTPS proxy: intercepted request handling and TLS upstream.
//!
//! The CONNECT handshake and TLS setup is in main.rs.
//! This module handles the decrypted HTTP requests after MITM.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use crate::config::{parse_timeout, CONFIG};
use crate::util::{error_response, is_hop_by_hop, MAX_BODY_BYTES, UPSTREAM_CLIENT};

/// Handle a decrypted HTTP request from the MITM stream.
///
/// Same logic as the plain HTTP proxy (domain check, credentials, path filter)
/// but forwards upstream over TLS.
pub async fn handle_intercepted_request(
    req: Request<Incoming>,
    domain: &str,
    port: u16,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path_and_query().map(|pq| pq.to_string()).unwrap_or_else(|| "/".to_string());

    let config = CONFIG.load();

    // Domain already checked in handle_connect, but re-check for safety
    if !config.is_allowed(domain) {
        access_log(domain, &method, &path, 403, start, 0, 0, false);
        return Ok(error_response(StatusCode::FORBIDDEN, "Domain not allowed"));
    }

    // Resolve devbox.local alias → real domain
    let (real_domain, is_alias) = if let Some(policy) = config.resolve_alias(domain) {
        (policy.domain.clone(), true)
    } else {
        (domain.to_string(), false)
    };

    if is_alias {
        tracing::debug!(alias = domain, domain = %real_domain, "MITM alias resolved");
    }

    let policy = config.get_policy(domain);

    // Read-only enforcement
    if let Some(p) = policy {
        if p.read_only && !matches!(method, hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS) {
            access_log(&real_domain, &method, &path, 403, start, 0, 0, false);
            return Ok(error_response(StatusCode::FORBIDDEN, "Write methods not allowed"));
        }
    }

    // Path filtering
    if let Some(p) = policy {
        if !p.allowed_paths.is_empty() {
            let path_allowed = p.allowed_paths.iter().any(|pattern| {
                if pattern.ends_with('*') {
                    path.starts_with(pattern.trim_end_matches('*'))
                } else {
                    path == pattern.as_str()
                }
            });
            if !path_allowed {
                access_log(&real_domain, &method, &path, 403, start, 0, 0, false);
                return Ok(error_response(StatusCode::FORBIDDEN, "Path not allowed"));
            }
        }
    }

    // Rate limiting
    if let Some(p) = policy {
        if let Some(rpm) = p.rate_limit_rpm {
            if !crate::config::check_rate_limit(&real_domain, rpm, p.burst_size) {
                access_log(&real_domain, &method, &path, 429, start, 0, 0, false);
                return Ok(error_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
            }
        }
    }

    // Build upstream request — pick scheme from per-domain `tls` flag.
    // tls defaults to true (HTTPS upstream); explicit `tls: false` keeps HTTP.
    // For HTTP upstreams the standard port is 80, not the MITM port.
    let use_tls = policy.map(|p| p.tls).unwrap_or(true);
    let (scheme, upstream_port) = if use_tls {
        ("https", port)
    } else {
        ("http", if port == 443 { 80 } else { port })
    };
    let upstream_url = format!("{}://{}:{}{}", scheme, real_domain, upstream_port, path);

    let mut upstream_req = Request::builder()
        .method(method.clone())
        .uri(&upstream_url);

    // Copy headers, skipping Host (we set it explicitly)
    for (name, value) in req.headers() {
        if !is_hop_by_hop(name.as_str()) && name != hyper::header::HOST {
            upstream_req = upstream_req.header(name, value);
        }
    }

    // Set Host header to the real domain (rewrites alias → real domain)
    upstream_req = upstream_req.header("Host", real_domain.as_str());

    // Add X-Real-Domain header
    upstream_req = upstream_req.header("X-Real-Domain", real_domain.as_str());

    // Credential injection
    let mut credential_injected = false;
    if let Some(p) = policy {
        if let (Some(header), Some(format), Some(value)) =
            (&p.credential_header, &p.credential_format, &p.credential_value)
        {
            let header_value = format.replace("{value}", value);
            upstream_req = upstream_req.header(header.as_str(), header_value);
            upstream_req = upstream_req.header("X-Credential-Injected", "true");
            credential_injected = true;
            tracing::debug!(domain = domain, "MITM credential injected");
        }
    }

    // Collect body (with size limit to prevent OOM)
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
            access_log(&real_domain, &method, &path, 403, start, 0, bytes_received, credential_injected);
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

    // Forward upstream (with per-domain timeout from policy)
    let upstream_timeout = parse_timeout(policy.and_then(|p| p.timeout.as_deref()));
    match tokio::time::timeout(upstream_timeout, forward_https(upstream_req)).await {
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
                tracing::error!(domain = %real_domain, error = %e, "MITM upstream error");
                access_log(&real_domain, &method, &path, 502, start, 0, bytes_received, credential_injected);
                Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream connection failed"))
            }
        }
    }
}

/// Emit a structured access log entry (same schema as proxy.rs).
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

/// Forward request to upstream.  Scheme (http/https) is set on the request URI
/// by the caller and dispatched by the shared mixed connector.
async fn forward_https(
    req: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = UPSTREAM_CLIENT.request(req).await?;
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

