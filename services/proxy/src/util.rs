//! Shared utilities for HTTP proxy handlers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

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
