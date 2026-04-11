//! SMTP send for generic password-auth accounts.
//!
//! Uses lettre with STARTTLS (port 587) — mirrors the Python legacy
//! provider's connect_smtp() behavior.

use base64::Engine;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Body, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::email::config::EmailAccount;
use crate::email::handler::EmailError;

/// Attachment body as base64-encoded content + filename + content type.
pub struct SendAttachment {
    pub filename: String,
    pub content_base64: String,
    pub content_type: String,
}

pub struct SendRequest<'a> {
    pub account: &'a EmailAccount,
    pub to: &'a [String],
    pub cc: &'a [String],
    pub bcc: &'a [String],
    pub subject: &'a str,
    pub body_text: &'a str,
    pub body_html: &'a str,
    pub attachments: &'a [SendAttachment],
}

/// Send an email via the account's SMTP server.  Returns the message ID.
pub async fn send(req: SendRequest<'_>) -> Result<String, EmailError> {
    let acct = req.account;
    let from: Mailbox = acct
        .email
        .parse()
        .map_err(|e| EmailError::BadRequest(format!("invalid From address: {}", e)))?;

    let mut builder = Message::builder().from(from.clone()).subject(req.subject);

    for addr in req.to {
        let mbox: Mailbox = addr
            .parse()
            .map_err(|e| EmailError::BadRequest(format!("invalid To address {}: {}", addr, e)))?;
        builder = builder.to(mbox);
    }
    for addr in req.cc {
        let mbox: Mailbox = addr
            .parse()
            .map_err(|e| EmailError::BadRequest(format!("invalid Cc address {}: {}", addr, e)))?;
        builder = builder.cc(mbox);
    }
    for addr in req.bcc {
        let mbox: Mailbox = addr
            .parse()
            .map_err(|e| EmailError::BadRequest(format!("invalid Bcc address {}: {}", addr, e)))?;
        builder = builder.bcc(mbox);
    }

    // Build the body.  Legacy service attaches text and/or html parts as
    // alternatives; if attachments are present, the whole thing wraps in
    // a mixed multipart.
    let text_part = if !req.body_text.is_empty() || (req.body_text.is_empty() && req.body_html.is_empty()) {
        Some(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(req.body_text.to_string()),
        )
    } else {
        None
    };
    let html_part = if !req.body_html.is_empty() {
        Some(
            SinglePart::builder()
                .header(ContentType::TEXT_HTML)
                .body(req.body_html.to_string()),
        )
    } else {
        None
    };

    let alternative = match (text_part, html_part) {
        (Some(t), Some(h)) => MultiPart::alternative().singlepart(t).singlepart(h),
        (Some(t), None) => MultiPart::alternative().singlepart(t),
        (None, Some(h)) => MultiPart::alternative().singlepart(h),
        (None, None) => unreachable!("text_part is always Some when both bodies empty"),
    };

    let msg = if req.attachments.is_empty() {
        builder
            .multipart(alternative)
            .map_err(|e| EmailError::BadRequest(format!("failed to build message: {}", e)))?
    } else {
        let mut mixed = MultiPart::mixed().multipart(alternative);
        for att in req.attachments {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&att.content_base64)
                .map_err(|e| EmailError::BadRequest(format!("attachment {}: invalid base64: {}", att.filename, e)))?;
            let content_type: ContentType = att
                .content_type
                .parse()
                .unwrap_or_else(|_| ContentType::parse("application/octet-stream").unwrap());
            let filename = sanitize_filename(&att.filename);
            mixed = mixed.singlepart(
                Attachment::new(filename).body(Body::new(decoded), content_type),
            );
        }
        builder
            .multipart(mixed)
            .map_err(|e| EmailError::BadRequest(format!("failed to build message: {}", e)))?
    };

    // SMTP client — STARTTLS on the configured port (legacy uses 587)
    let creds = Credentials::new(
        acct.login_username().to_string(),
        acct.credential.password.clone(),
    );

    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&acct.smtp_server)
            .map_err(|e| EmailError::Upstream(format!("SMTP relay setup: {}", e)))?
            .port(acct.smtp_port)
            .credentials(creds)
            .build();

    mailer
        .send(msg.clone())
        .await
        .map_err(|e| EmailError::Upstream(format!("SMTP send: {}", e)))?;

    // Message-ID is set by lettre during send.  We extract from the Message
    // headers if present; otherwise return a synthetic id.
    let id = extract_message_id(&msg)
        .unwrap_or_else(|| format!("<{}-{}@cagent-proxy>", acct.name, now_millis()));
    Ok(id)
}

fn extract_message_id(msg: &Message) -> Option<String> {
    // lettre 0.11 doesn't expose Message-ID directly; rely on the
    // formatted message bytes and regex-free line scan.
    let bytes = msg.formatted();
    let text = std::str::from_utf8(&bytes).ok()?;
    for line in text.lines() {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some(rest) = line.strip_prefix("Message-ID:") {
            return Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("Message-Id:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn sanitize_filename(name: &str) -> String {
    let stripped: String = name
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0' | '/' | '\\'))
        .collect();
    let trimmed = if stripped.len() > 255 {
        stripped[..255].to_string()
    } else {
        stripped
    };
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed
    }
}
