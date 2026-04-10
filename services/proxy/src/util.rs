//! Shared utilities for HTTP proxy handlers.

use std::sync::LazyLock;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// Shared upstream client that handles both HTTP and HTTPS schemes.
///
/// The hyper-rustls connector inspects each request URI: `https://` upstreams
/// go through TLS, `http://` upstreams go plain.  One pooled client serves
/// both proxy.rs (plain HTTP-in) and mitm.rs (decrypted HTTPS-in) and lets
/// the per-domain `tls` flag control upstream scheme.
pub static UPSTREAM_CLIENT: LazyLock<
    Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(connector)
});

/// Check if a header is hop-by-hop (should not be forwarded).
pub fn is_hop_by_hop(name: &str) -> bool {
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
pub fn error_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Maximum request body size (10 MB).  Requests larger than this are
/// rejected with 413 to prevent a malicious cell from OOM-killing the
/// proxy (which has a 32 MB memory limit).
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
