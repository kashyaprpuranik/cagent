//! Config push HTTP endpoint.
//!
//! Warden pushes config updates via POST /config.
//! The proxy swaps config atomically using arc-swap.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use crate::config::{self, ProxyConfig};

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

/// POST /config — update proxy configuration.
async fn handle_config_push(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
async fn handle_config_get() -> Result<Response<Full<Bytes>>, hyper::Error> {
    let config = config::CONFIG.load();
    let json = serde_json::to_string_pretty(&**config).unwrap_or_default();
    Ok(json_response(StatusCode::OK, &json))
}

fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
