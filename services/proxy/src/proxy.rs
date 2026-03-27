//! HTTP forward proxy handler.
//!
//! Accepts plain HTTP requests (non-CONNECT), checks domain allowlist,
//! injects credentials, and forwards upstream.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use crate::config::CONFIG;

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
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Extract host from the request (Host header or URI authority)
    let host = extract_host(&req).unwrap_or_default();

    if host.is_empty() {
        return Ok(error_response(StatusCode::BAD_REQUEST, "Missing host"));
    }

    // Strip port from host for domain matching
    let domain = host.split(':').next().unwrap_or(&host);

    // Load current config (lock-free)
    let config = CONFIG.load();

    // 1. Domain allowlist check
    if !config.is_allowed(domain) {
        tracing::info!(domain = domain, method = %method, "blocked: domain not in allowlist");
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
            tracing::info!(domain = domain, method = %method, "blocked: read-only domain");
            return Ok(error_response(StatusCode::FORBIDDEN, "Write methods not allowed for this domain"));
        }
    }

    // 3. Path filtering
    if let Some(p) = policy {
        if !p.allowed_paths.is_empty() {
            let path = uri.path();
            let path_allowed = p.allowed_paths.iter().any(|pattern| {
                if pattern.ends_with('*') {
                    path.starts_with(pattern.trim_end_matches('*'))
                } else {
                    path == pattern
                }
            });
            if !path_allowed {
                tracing::info!(domain = domain, path = path, "blocked: path not allowed");
                return Ok(error_response(StatusCode::FORBIDDEN, "Path not allowed"));
            }
        }
    }

    // 4. Build upstream request
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

    // 5. Credential injection
    if let Some(p) = policy {
        if let (Some(header), Some(format), Some(value)) =
            (&p.credential_header, &p.credential_format, &p.credential_value)
        {
            let header_value = format.replace("{value}", value);
            upstream_req = upstream_req.header(header.as_str(), header_value);
            tracing::debug!(domain = domain, header = header.as_str(), "credential injected");
        }
    }

    // Collect request body
    let body_bytes = req.collect().await?.to_bytes();

    let upstream_req = upstream_req
        .body(Full::new(body_bytes.clone()))
        .unwrap();

    // 6. Forward upstream
    match forward_upstream(upstream_req).await {
        Ok(resp) => {
            tracing::info!(
                domain = domain,
                method = %method,
                status = resp.status().as_u16(),
                "proxied"
            );
            Ok(resp)
        }
        Err(e) => {
            tracing::error!(domain = domain, error = %e, "upstream error");
            Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream connection failed"))
        }
    }
}

/// Forward request to the upstream server.
async fn forward_upstream(
    req: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client.request(req).await?;

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

/// Check if a header is hop-by-hop (should not be forwarded).
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Build a simple error response.
fn error_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
