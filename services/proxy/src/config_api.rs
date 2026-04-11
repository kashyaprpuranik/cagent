//! Config push HTTP endpoint.
//!
//! Warden pushes config updates via POST /config.
//! The proxy swaps config atomically using arc-swap.
//!
//! Security: when `CAGENT_PROXY_TOKEN` is set, POST /config requires an
//! `X-Config-Token` header matching the token.  GET /config redacts
//! credentials before returning to avoid leaking them to any peer on
//! infra-net that can reach port 18080.

use std::sync::LazyLock;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use subtle::ConstantTimeEq;

use crate::config::{self, ProxyConfig};

/// Shared secret required for config pushes.  Empty → auth disabled (dev).
static CONFIG_TOKEN: LazyLock<Option<String>> = LazyLock::new(|| {
    std::env::var("CAGENT_PROXY_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
});

/// Handle config API requests (separate listener from the proxy).
pub async fn handle_config_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::POST, "/config") => handle_config_push(req).await,
        (&hyper::Method::GET, "/health") => Ok(json_response(
            StatusCode::OK,
            r#"{"status":"ok"}"#,
        )),
        (&hyper::Method::GET, "/config") => handle_config_get().await,
        _ => Ok(json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)),
    }
}

/// Verify `X-Config-Token` against `CAGENT_PROXY_TOKEN`.
///
/// Returns `Ok(())` if auth is disabled (no token configured) or the header
/// matches.  Uses a constant-time comparison to avoid timing side channels.
fn verify_config_token(req: &Request<Incoming>) -> Result<(), Response<Full<Bytes>>> {
    let Some(expected) = CONFIG_TOKEN.as_deref() else {
        // Dev / standalone: no token configured.  Warn once on first use
        // (handled at startup) and allow.
        return Ok(());
    };

    let provided = req
        .headers()
        .get("x-config-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        tracing::warn!("config push rejected: invalid or missing X-Config-Token");
        Err(json_response(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid or missing X-Config-Token"}"#,
        ))
    }
}

/// POST /config — update proxy configuration.
async fn handle_config_push(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Err(resp) = verify_config_token(&req) {
        return Ok(resp);
    }

    let body = req.collect().await?.to_bytes();

    match serde_json::from_slice::<ProxyConfig>(&body) {
        Ok(new_config) => {
            let domain_count = new_config.domains.len();
            config::update_config(new_config);
            Ok(json_response(
                StatusCode::OK,
                &format!(r#"{{"status":"updated","domains":{}}}"#, domain_count),
            ))
        }
        Err(e) => {
            tracing::warn!(error = %e, "invalid config push");
            Ok(json_response(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"invalid config: {}"}}"#, e),
            ))
        }
    }
}

/// GET /config — return current config (for debugging).
///
/// Credentials are redacted: `credential_value` is replaced with `"<redacted>"`
/// when set, or omitted when absent.  This preserves visibility into *which*
/// domains have credentials configured without exposing the secret itself.
async fn handle_config_get() -> Result<Response<Full<Bytes>>, hyper::Error> {
    let config = config::CONFIG.load();
    let redacted = config.redacted_for_display();
    let json = serde_json::to_string_pretty(&redacted).unwrap_or_default();
    Ok(json_response(StatusCode::OK, &json))
}

/// Log the initial auth state once at startup so operators notice an
/// unauthenticated config API in production deployments.
pub fn log_auth_status() {
    if CONFIG_TOKEN.is_some() {
        tracing::info!("config API auth enabled (CAGENT_PROXY_TOKEN set)");
    } else {
        tracing::warn!(
            "config API auth DISABLED: CAGENT_PROXY_TOKEN not set. \
             Any peer on infra-net can push config.  Set CAGENT_PROXY_TOKEN \
             in production."
        );
    }
}

fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
