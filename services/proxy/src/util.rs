//! Shared utilities for HTTP proxy handlers.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body, Incoming};
use hyper::{Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// Boxed dynamic error used by the proxy body type.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Type-erased streaming body returned by both proxy.rs and mitm.rs.
/// `Full<Bytes>` (small in-memory buffers, used for error responses) and
/// hyper's `Incoming` (streaming upstream responses) both box into this.
/// `UnsyncBoxBody` (rather than `BoxBody`) drops the `Sync` requirement
/// because hyper's `Incoming` body is `Send` but not `Sync`.
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

/// Convenience alias for the response type both proxy paths return.
pub type ProxyResponse = Response<ProxyBody>;

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

/// Build a simple error response with an in-memory body.
pub fn error_response(status: StatusCode, body: &str) -> ProxyResponse {
    let body_bytes = Bytes::from(body.to_string());
    let body: ProxyBody = Full::new(body_bytes)
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed_unsync();
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(body)
        .unwrap()
}

/// Maximum request body size (10 MB).  Requests larger than this are
/// rejected with 413 to prevent a malicious cell from OOM-killing the
/// proxy (which has a 32 MB memory limit).
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Streaming response body with deferred access logging
// ---------------------------------------------------------------------------

/// Captured request metadata that the access log line needs.  Held inside
/// `AccessLogGuard` so the log fires when the response body finishes
/// streaming (whether successfully or due to client disconnect).
pub struct AccessLogContext {
    pub domain: String,
    pub method: hyper::Method,
    pub path: String,
    pub response_code: u16,
    pub start: Instant,
    pub bytes_received: usize,
    pub credential_injected: bool,
}

/// Drop guard that emits the access log line when the wrapping body is
/// fully consumed (or aborted).  Holds an atomic counter that the body
/// adapter increments on each frame.
pub struct AccessLogGuard {
    ctx: AccessLogContext,
    bytes_sent: AtomicUsize,
}

impl AccessLogGuard {
    fn add_bytes(&self, n: usize) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }
}

impl Drop for AccessLogGuard {
    fn drop(&mut self) {
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        emit_access_log(&self.ctx, bytes_sent);
    }
}

fn emit_access_log(ctx: &AccessLogContext, bytes_sent: usize) {
    let duration = ctx.start.elapsed().as_millis() as u64;
    tracing::info!(
        method = %ctx.method,
        path = ctx.path.as_str(),
        authority = ctx.domain.as_str(),
        upstream_host = ctx.domain.as_str(),
        response_code = ctx.response_code,
        duration = duration,
        bytes_sent = bytes_sent,
        bytes_received = ctx.bytes_received,
        credential_injected = ctx.credential_injected,
        "access"
    );
}

/// Emit an access log entry immediately for terminal exit paths (block,
/// timeout, error) where there's no upstream body to stream.  bytes_sent
/// is always 0 for these paths.
pub fn access_log_now(ctx: AccessLogContext) {
    emit_access_log(&ctx, 0);
}

/// Wrap a streaming upstream body so that:
/// 1. Each frame's data length is added to the byte counter
/// 2. When the body is dropped, the AccessLogGuard's Drop fires and emits
///    a structured access log line with the actual bytes_sent
///
/// This lets us stream the response body to the client (instead of buffering
/// it all in memory) while still recording accurate bandwidth metrics for
/// the analytics pipeline.
pub fn instrument_response_body<B>(body: B, ctx: AccessLogContext) -> ProxyBody
where
    B: Body<Data = Bytes, Error = hyper::Error> + Send + 'static,
{
    let guard = Arc::new(AccessLogGuard {
        ctx,
        bytes_sent: AtomicUsize::new(0),
    });

    body.map_err(|e| Box::new(e) as BoxError)
        .map_frame(move |frame| {
            if let Some(data) = frame.data_ref() {
                guard.add_bytes(data.len());
            }
            frame
        })
        .boxed_unsync()
}

/// Box an `Incoming` body without instrumentation.  Used when there's no
/// access log to attach (shouldn't happen in normal flows, but kept as a
/// helper for completeness).
#[allow(dead_code)]
pub fn box_incoming(body: Incoming) -> ProxyBody {
    body.map_err(|e| Box::new(e) as BoxError).boxed_unsync()
}
