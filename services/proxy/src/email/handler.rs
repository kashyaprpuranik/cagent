//! HTTP handler mapping /health, /send, /inbox, /message, /attachment,
//! /folders, /accounts, /reload to the IMAP/SMTP backends.
//!
//! Called from proxy.rs when the request host matches the configured email
//! alias (email.devbox.local by default).  Returns ProxyResponse so it can
//! be returned from handle_request directly.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use serde::Deserialize;

use crate::config::CONFIG;
use crate::email::config::EmailAccount;
use crate::email::policy::{check_rate_limit, check_recipients_allowed, check_sender_allowed, RateAction};
use crate::email::{imap, smtp};
use crate::util::{error_response, ProxyBody, ProxyResponse};

/// Error shared by smtp/imap modules.  Converted to ProxyResponse via `into_response`.
///
/// Forbidden/RateLimited are NOT produced by the backend modules (smtp.rs /
/// imap.rs) — those conditions are enforced at the handler level where the
/// full policy context is available — but the variants exist so the handler
/// can use one type end-to-end if future backends need to surface them.
#[derive(Debug)]
#[allow(dead_code)]
pub enum EmailError {
    BadRequest(String),
    NotFound(String),
    Forbidden(String),
    RateLimited(String),
    Upstream(String),
}

impl EmailError {
    fn into_response(self) -> ProxyResponse {
        let (status, msg) = match self {
            EmailError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            EmailError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            EmailError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            EmailError::RateLimited(m) => (StatusCode::TOO_MANY_REQUESTS, m),
            EmailError::Upstream(m) => (StatusCode::BAD_GATEWAY, m),
        };
        json_error(status, &msg)
    }
}

/// Dispatch a request routed to `email.devbox.local` to the in-process
/// email handlers.  Returns None if the path doesn't match any known
/// endpoint so the caller can serve a 404.
pub async fn handle(req: Request<Incoming>) -> ProxyResponse {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();

    match (method.clone(), path.as_str()) {
        (hyper::Method::GET, "/health") => health(),
        (hyper::Method::POST, "/reload") => reload(),
        (hyper::Method::GET, "/accounts") => list_accounts(),
        (hyper::Method::POST, "/send") => send(req).await,
        (hyper::Method::GET, "/inbox") => list_inbox(&query).await,
        (hyper::Method::POST, "/folders") => list_folders(req).await,
        (hyper::Method::GET, p) if p.starts_with("/message/") => {
            let uid = &p["/message/".len()..];
            if uid.is_empty() {
                error_response(StatusCode::BAD_REQUEST, "missing uid")
            } else {
                get_message(uid, &query).await
            }
        }
        (hyper::Method::GET, p) if p.starts_with("/attachment/") => {
            let rest = &p["/attachment/".len()..];
            let mut it = rest.splitn(2, '/');
            match (it.next(), it.next()) {
                (Some(uid), Some(part)) if !uid.is_empty() && !part.is_empty() => {
                    get_attachment(uid, part, &query).await
                }
                _ => error_response(StatusCode::BAD_REQUEST, "path must be /attachment/{uid}/{part_id}"),
            }
        }
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn health() -> ProxyResponse {
    let count = CONFIG.load().email_accounts.len();
    json_response(StatusCode::OK, &format!(r#"{{"status":"ok","accounts":{}}}"#, count))
}

fn reload() -> ProxyResponse {
    // Config is pushed from warden via the main config API, so /reload is
    // a no-op — it exists for compatibility with the legacy Python service.
    let count = CONFIG.load().email_accounts.len();
    json_response(StatusCode::OK, &format!(r#"{{"status":"ok","accounts":{}}}"#, count))
}

fn list_accounts() -> ProxyResponse {
    let config = CONFIG.load();
    let accounts: Vec<serde_json::Value> = config
        .email_accounts
        .iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "email": a.email,
                "imap_server": a.imap_server,
                "smtp_server": a.smtp_server,
            })
        })
        .collect();
    let body = serde_json::json!({"accounts": accounts}).to_string();
    json_response(StatusCode::OK, &body)
}

#[derive(Deserialize)]
struct SendBody {
    account: String,
    to: Vec<String>,
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    html: String,
    #[serde(default)]
    cc: Option<Vec<String>>,
    #[serde(default)]
    bcc: Option<Vec<String>>,
    #[serde(default)]
    attachments: Option<Vec<SendAttachmentBody>>,
}

#[derive(Deserialize)]
struct SendAttachmentBody {
    filename: String,
    content_base64: String,
    #[serde(default = "default_content_type")]
    content_type: String,
}

fn default_content_type() -> String {
    "application/octet-stream".to_string()
}

async fn send(req: Request<Incoming>) -> ProxyResponse {
    let body = match collect_body(req).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let parsed: SendBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
    };

    let Some(acct) = find_account(&parsed.account) else {
        return json_error(StatusCode::NOT_FOUND, &format!("Account not found: {}", parsed.account));
    };

    // Policy: check recipients
    let mut all_recipients: Vec<String> = parsed.to.clone();
    if let Some(cc) = &parsed.cc {
        all_recipients.extend(cc.iter().cloned());
    }
    if let Some(bcc) = &parsed.bcc {
        all_recipients.extend(bcc.iter().cloned());
    }
    let disallowed = check_recipients_allowed(&all_recipients, &acct.policy);
    if !disallowed.is_empty() {
        return json_error(
            StatusCode::FORBIDDEN,
            &format!("Recipients not allowed by policy: {}", disallowed.join(", ")),
        );
    }

    // Policy: rate limit
    if !check_rate_limit(&acct.name, RateAction::Send, &acct.policy) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!(
                "Send rate limit exceeded for account {} ({}/hour)",
                acct.name, acct.policy.sends_per_hour
            ),
        );
    }

    let attachments: Vec<smtp::SendAttachment> = parsed
        .attachments
        .unwrap_or_default()
        .into_iter()
        .map(|a| smtp::SendAttachment {
            filename: a.filename,
            content_base64: a.content_base64,
            content_type: a.content_type,
        })
        .collect();

    let cc: Vec<String> = parsed.cc.unwrap_or_default();
    let bcc: Vec<String> = parsed.bcc.unwrap_or_default();

    let send_req = smtp::SendRequest {
        account: &acct,
        to: &parsed.to,
        cc: &cc,
        bcc: &bcc,
        subject: &parsed.subject,
        body_text: &parsed.body,
        body_html: &parsed.html,
        attachments: &attachments,
    };

    match smtp::send(send_req).await {
        Ok(message_id) => {
            let body = serde_json::json!({
                "status": "sent",
                "message_id": message_id,
            })
            .to_string();
            json_response(StatusCode::OK, &body)
        }
        Err(e) => {
            tracing::warn!(account = %acct.name, error = ?e, "email send failed");
            e.into_response()
        }
    }
}

async fn list_inbox(query: &str) -> ProxyResponse {
    let params = parse_query(query);
    let account = match params.get("account") {
        Some(a) => a.clone(),
        None => return error_response(StatusCode::BAD_REQUEST, "missing 'account' query param"),
    };
    let Some(acct) = find_account(&account) else {
        return json_error(StatusCode::NOT_FOUND, &format!("Account not found: {}", account));
    };
    if !check_rate_limit(&acct.name, RateAction::Read, &acct.policy) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!(
                "Read rate limit exceeded for account {} ({}/hour)",
                acct.name, acct.policy.reads_per_hour
            ),
        );
    }

    let folder = params.get("folder").cloned().unwrap_or_else(|| "INBOX".to_string());
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
        .clamp(1, 100);
    let since = params.get("since").cloned();
    let from_filter = params.get("from_filter").cloned();

    match imap::list_messages(&acct, &folder, limit, since.as_deref(), from_filter.as_deref()).await {
        Ok(msgs) => {
            let filtered: Vec<imap::MessageSummary> = msgs
                .into_iter()
                .filter(|m| check_sender_allowed(&m.from, &acct.policy))
                .collect();
            let body = serde_json::json!({"messages": filtered}).to_string();
            json_response(StatusCode::OK, &body)
        }
        Err(e) => {
            tracing::warn!(account = %acct.name, error = ?e, "email inbox failed");
            e.into_response()
        }
    }
}

async fn get_message(uid: &str, query: &str) -> ProxyResponse {
    let params = parse_query(query);
    let Some(account) = params.get("account").cloned() else {
        return error_response(StatusCode::BAD_REQUEST, "missing 'account' query param");
    };
    let Some(acct) = find_account(&account) else {
        return json_error(StatusCode::NOT_FOUND, &format!("Account not found: {}", account));
    };
    if !check_rate_limit(&acct.name, RateAction::Read, &acct.policy) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Read rate limit exceeded for account {}", acct.name),
        );
    }
    let folder = params.get("folder").cloned().unwrap_or_else(|| "INBOX".to_string());
    match imap::get_message(&acct, uid, &folder).await {
        Ok(msg) => {
            if !check_sender_allowed(&msg.from, &acct.policy) {
                return json_error(StatusCode::FORBIDDEN, "Sender not in allowed list");
            }
            let body = serde_json::to_string(&msg).unwrap_or_else(|_| "{}".to_string());
            json_response(StatusCode::OK, &body)
        }
        Err(e) => {
            tracing::warn!(account = %acct.name, uid = uid, error = ?e, "email get_message failed");
            e.into_response()
        }
    }
}

async fn get_attachment(uid: &str, part_id: &str, query: &str) -> ProxyResponse {
    let params = parse_query(query);
    let Some(account) = params.get("account").cloned() else {
        return error_response(StatusCode::BAD_REQUEST, "missing 'account' query param");
    };
    let Some(acct) = find_account(&account) else {
        return json_error(StatusCode::NOT_FOUND, &format!("Account not found: {}", account));
    };
    if !check_rate_limit(&acct.name, RateAction::Read, &acct.policy) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Read rate limit exceeded for account {}", acct.name),
        );
    }
    let folder = params.get("folder").cloned().unwrap_or_else(|| "INBOX".to_string());
    match imap::get_attachment(&acct, uid, part_id, &folder).await {
        Ok(blob) => {
            let sanitized = sanitize_filename(&blob.filename);
            let body: ProxyBody = Full::new(Bytes::from(blob.data))
                .map_err(|never: std::convert::Infallible| match never {})
                .boxed_unsync();
            let builder = hyper::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", blob.content_type)
                .header(
                    "Content-Disposition",
                    format!(r#"attachment; filename="{}""#, sanitized),
                );
            // If the above fails (it shouldn't), fall back to a plain error
            match builder.body(body) {
                Ok(r) => r,
                Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"),
            }
        }
        Err(e) => {
            tracing::warn!(account = %acct.name, uid = uid, part_id = part_id, error = ?e, "email get_attachment failed");
            e.into_response()
        }
    }
}

async fn list_folders(req: Request<Incoming>) -> ProxyResponse {
    let body = match collect_body(req).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
    };
    let Some(account) = parsed.get("account").and_then(|v| v.as_str()).map(|s| s.to_string()) else {
        return error_response(StatusCode::BAD_REQUEST, "missing 'account' field");
    };
    let Some(acct) = find_account(&account) else {
        return json_error(StatusCode::NOT_FOUND, &format!("Account not found: {}", account));
    };
    if !check_rate_limit(&acct.name, RateAction::Read, &acct.policy) {
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Read rate limit exceeded for account {}", acct.name),
        );
    }
    match imap::list_folders(&acct).await {
        Ok(folders) => {
            let body = serde_json::json!({"folders": folders}).to_string();
            json_response(StatusCode::OK, &body)
        }
        Err(e) => {
            tracing::warn!(account = %acct.name, error = ?e, "email list_folders failed");
            e.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_account(name: &str) -> Option<EmailAccount> {
    CONFIG
        .load()
        .email_accounts
        .iter()
        .find(|a| a.name == name)
        .cloned()
}

async fn collect_body(req: Request<Incoming>) -> Result<Bytes, EmailError> {
    req.collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| EmailError::BadRequest(format!("failed to read body: {}", e)))
}

fn parse_query(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            Some((url_decode(k), url_decode(v)))
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    // application/x-www-form-urlencoded: + → space, then percent-decode.
    // Use percent-encoding crate so multi-byte UTF-8 sequences are
    // decoded correctly and invalid sequences pass through as the raw
    // replacement character.
    let plus_to_space: String = s.chars().map(|c| if c == '+' { ' ' } else { c }).collect();
    percent_encoding::percent_decode_str(&plus_to_space)
        .decode_utf8_lossy()
        .into_owned()
}

fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0' | '/' | '\\' | '"'))
        .take(255)
        .collect();
    if cleaned.is_empty() {
        "attachment".to_string()
    } else {
        cleaned
    }
}

fn json_response(status: StatusCode, body: &str) -> ProxyResponse {
    let body: ProxyBody = Full::new(Bytes::from(body.to_string()))
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed_unsync();
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap()
}

fn json_error(status: StatusCode, msg: &str) -> ProxyResponse {
    // Match FastAPI's {"detail": "..."} error shape for compatibility with
    // the Python service's clients.  Use serde_json so control chars,
    // backslashes, and unicode in error messages are escaped correctly.
    let body = serde_json::json!({ "detail": msg }).to_string();
    json_response(status, &body)
}
