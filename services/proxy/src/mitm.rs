//! MITM HTTPS proxy: intercepted request handling and TLS upstream.
//!
//! The CONNECT handshake and TLS setup is in main.rs.
//! This module handles the decrypted HTTP requests after MITM.

use std::sync::LazyLock;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::config::CONFIG;

/// Shared HTTPS client for connection pooling to upstream servers.
static HTTPS_CLIENT: LazyLock<Client<hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(https_connector)
});

/// Handle a decrypted HTTP request from the MITM stream.
///
/// Same logic as the plain HTTP proxy (domain check, credentials, path filter)
/// but forwards upstream over TLS.
pub async fn handle_intercepted_request(
    req: Request<Incoming>,
    domain: &str,
    port: u16,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let config = CONFIG.load();

    // Domain already checked in handle_connect, but re-check for safety
    if !config.is_allowed(domain) {
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
            tracing::info!(domain = domain, method = %method, "MITM blocked: read-only domain");
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
                tracing::info!(domain = domain, path = path, "MITM blocked: path not allowed");
                return Ok(error_response(StatusCode::FORBIDDEN, "Path not allowed"));
            }
        }
    }

    // Build upstream HTTPS request (use real domain for aliases)
    let upstream_url = format!("https://{}:{}{}", real_domain, port, path);

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
    if let Some(p) = policy {
        if let (Some(header), Some(format), Some(value)) =
            (&p.credential_header, &p.credential_format, &p.credential_value)
        {
            let header_value = format.replace("{value}", value);
            upstream_req = upstream_req.header(header.as_str(), header_value);
            upstream_req = upstream_req.header("X-Credential-Injected", "true");
            tracing::debug!(domain = domain, "MITM credential injected");
        }
    }

    // Collect body
    let body_bytes = req.collect().await?.to_bytes();

    // TODO Phase 2b: DLP scanning on body_bytes here

    let upstream_req = upstream_req
        .body(Full::new(body_bytes))
        .unwrap();

    // Forward upstream over HTTPS (with timeout)
    match tokio::time::timeout(std::time::Duration::from_secs(30), forward_https(upstream_req)).await {
        Err(_) => {
            tracing::warn!(domain = %real_domain, "MITM upstream timeout (30s)");
            Ok(error_response(StatusCode::GATEWAY_TIMEOUT, "Upstream request timed out"))
        }
        Ok(result) => match result {
            Ok(resp) => {
                tracing::info!(
                    domain = %real_domain,
                    method = %method,
                    path = path,
                    status = resp.status().as_u16(),
                    "MITM proxied"
                );
                Ok(resp)
            }
            Err(e) => {
                tracing::error!(domain = %real_domain, error = %e, "MITM upstream error");
                Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream connection failed"))
            }
        }
    }
}

/// Forward request to upstream over HTTPS (TLS).
async fn forward_https(
    req: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = HTTPS_CLIENT.request(req).await?;
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

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization"
            | "te" | "trailers" | "transfer-encoding" | "upgrade"
    )
}

fn error_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
