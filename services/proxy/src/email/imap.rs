//! IMAP read operations for generic password-auth accounts.
//!
//! Uses async-imap over tokio-rustls (port 993 with implicit TLS).
//! Mirrors the Python legacy provider's behavior: fresh connection per
//! request, LOGIN with username/password, SELECT folder readonly,
//! SEARCH + FETCH, then LOGOUT.

use std::sync::Arc;

use async_imap::Session;
use futures_util::StreamExt;
use mail_parser::{MessageParser, MimeHeaders, PartType};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::email::config::EmailAccount;
use crate::email::handler::EmailError;

type ImapSession = Session<TlsStream<TcpStream>>;

/// Message summary matching the Python legacy response shape.
#[derive(Debug, serde::Serialize)]
pub struct MessageSummary {
    pub uid: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub snippet: String,
}

/// Full message response matching the Python legacy shape.
#[derive(Debug, serde::Serialize)]
pub struct FullMessage {
    pub uid: String,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub subject: String,
    pub date: String,
    pub body: String,
    pub html: String,
    pub attachments: Vec<AttachmentMeta>,
}

#[derive(Debug, serde::Serialize)]
pub struct AttachmentMeta {
    pub part_id: String,
    pub filename: String,
    pub content_type: String,
    pub size: usize,
}

/// Raw attachment bytes + metadata.
pub struct AttachmentBlob {
    pub data: Vec<u8>,
    pub filename: String,
    pub content_type: String,
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

async fn connect(account: &EmailAccount) -> Result<ImapSession, EmailError> {
    let addr = format!("{}:{}", account.imap_server, account.imap_port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| EmailError::Upstream(format!("IMAP connect {}: {}", addr, e)))?;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = ServerName::try_from(account.imap_server.clone())
        .map_err(|_| EmailError::Upstream(format!("invalid IMAP hostname: {}", account.imap_server)))?;

    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| EmailError::Upstream(format!("IMAP TLS handshake: {}", e)))?;

    let client = async_imap::Client::new(tls);
    let session = client
        .login(account.login_username(), &account.credential.password)
        .await
        .map_err(|(e, _client)| EmailError::Upstream(format!("IMAP login: {}", e)))?;

    Ok(session)
}

async fn disconnect(mut session: ImapSession) {
    let _ = session.logout().await;
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// List messages in a folder.  Supports optional `since` (YYYY-MM-DD) and
/// `from_filter` (IMAP FROM search, quoted).  Returns newest-first up to
/// `limit` messages with headers only (no body).
pub async fn list_messages(
    account: &EmailAccount,
    folder: &str,
    limit: usize,
    since: Option<&str>,
    from_filter: Option<&str>,
) -> Result<Vec<MessageSummary>, EmailError> {
    let mut session = connect(account).await?;

    session
        .examine(folder)
        .await
        .map_err(|e| EmailError::Upstream(format!("SELECT {}: {}", folder, e)))?;

    // Build IMAP SEARCH criteria
    let mut criteria: Vec<String> = Vec::new();
    if let Some(s) = since {
        if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            criteria.push(format!("SINCE {}", date.format("%d-%b-%Y")));
        } else {
            disconnect(session).await;
            return Err(EmailError::BadRequest(format!(
                "invalid 'since' format (expected YYYY-MM-DD): {}",
                s
            )));
        }
    }
    if let Some(f) = from_filter {
        criteria.push(format!("FROM \"{}\"", escape_imap_string(f)));
    }
    let search_str = if criteria.is_empty() {
        "ALL".to_string()
    } else {
        criteria.join(" ")
    };

    let uids_result = session
        .search(&search_str)
        .await
        .map_err(|e| EmailError::Upstream(format!("SEARCH {}: {}", folder, e)))?;

    // async-imap returns a HashSet<u32>
    let mut uids: Vec<u32> = uids_result.into_iter().collect();
    uids.sort_unstable();
    let start = uids.len().saturating_sub(limit);
    let selected: Vec<u32> = uids.drain(start..).collect();

    // Bulk FETCH all selected sequence numbers in a single round trip.
    // The previous implementation issued one FETCH per message (O(N)
    // round trips); IMAP supports comma-separated sequence sets so the
    // server can stream all headers in one response.
    let mut summaries: Vec<MessageSummary> = Vec::new();
    if !selected.is_empty() {
        let seq_set: String = selected
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Collect into a temporary map keyed by sequence number so we can
        // re-order to newest-first regardless of the order the server returns.
        let mut by_seq: std::collections::HashMap<u32, MessageSummary> =
            std::collections::HashMap::with_capacity(selected.len());

        let mut fetch_stream = session
            .fetch(&seq_set, "(RFC822.HEADER)")
            .await
            .map_err(|e| EmailError::Upstream(format!("FETCH headers: {}", e)))?;
        while let Some(item) = fetch_stream.next().await {
            let fetch = item.map_err(|e| EmailError::Upstream(format!("FETCH parse: {}", e)))?;
            let seq = fetch.message;
            let header_bytes: &[u8] = fetch.header().unwrap_or(&[]);
            let parser = MessageParser::new();
            if let Some(parsed) = parser.parse(header_bytes) {
                let (from, to, subject, date) = extract_headers(&parsed);
                by_seq.insert(
                    seq,
                    MessageSummary {
                        uid: seq.to_string(),
                        snippet: truncate(&subject, 100),
                        from,
                        to,
                        subject,
                        date,
                    },
                );
            }
        }
        drop(fetch_stream);

        // Re-order newest-first using the original selected order.
        for &seq in selected.iter().rev() {
            if let Some(s) = by_seq.remove(&seq) {
                summaries.push(s);
            }
        }
    }

    disconnect(session).await;
    Ok(summaries)
}

/// Fetch a full message body by sequence number.  Parses MIME and
/// returns plain text + HTML + attachment metadata.
pub async fn get_message(
    account: &EmailAccount,
    uid: &str,
    folder: &str,
) -> Result<FullMessage, EmailError> {
    let mut session = connect(account).await?;
    session
        .examine(folder)
        .await
        .map_err(|e| EmailError::Upstream(format!("SELECT {}: {}", folder, e)))?;

    let raw = fetch_rfc822(&mut session, uid).await?;
    disconnect(session).await;

    let parser = MessageParser::new();
    let parsed = parser
        .parse(&raw[..])
        .ok_or_else(|| EmailError::Upstream(format!("failed to parse message {}", uid)))?;

    let (from, to, subject, date) = extract_headers(&parsed);
    let cc = parsed
        .cc()
        .map(format_address)
        .unwrap_or_default();

    let body_text = parsed
        .body_text(0)
        .map(|c| c.to_string())
        .unwrap_or_default();
    let body_html = parsed
        .body_html(0)
        .map(|c| c.to_string())
        .unwrap_or_default();

    let attachments: Vec<AttachmentMeta> = parsed
        .attachments()
        .enumerate()
        .map(|(idx, part)| {
            let filename = part
                .attachment_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("attachment_{}", idx));
            let content_type = part_content_type(part);
            let size = part_content_len(part);
            AttachmentMeta {
                part_id: idx.to_string(),
                filename,
                content_type,
                size,
            }
        })
        .collect();

    Ok(FullMessage {
        uid: uid.to_string(),
        from,
        to,
        cc,
        subject,
        date,
        body: body_text,
        html: body_html,
        attachments,
    })
}

/// Fetch one attachment's raw bytes.  `part_id` is the 0-indexed attachment
/// index from `get_message`.
pub async fn get_attachment(
    account: &EmailAccount,
    uid: &str,
    part_id: &str,
    folder: &str,
) -> Result<AttachmentBlob, EmailError> {
    let target_idx: usize = part_id
        .parse()
        .map_err(|_| EmailError::BadRequest(format!("invalid part_id: {}", part_id)))?;

    let mut session = connect(account).await?;
    session
        .examine(folder)
        .await
        .map_err(|e| EmailError::Upstream(format!("SELECT {}: {}", folder, e)))?;
    let raw = fetch_rfc822(&mut session, uid).await?;
    disconnect(session).await;

    let parser = MessageParser::new();
    let parsed = parser
        .parse(&raw[..])
        .ok_or_else(|| EmailError::Upstream(format!("failed to parse message {}", uid)))?;

    let part = parsed
        .attachments()
        .nth(target_idx)
        .ok_or_else(|| EmailError::NotFound(format!("attachment part {} not found", part_id)))?;

    let filename = part
        .attachment_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("attachment_{}", target_idx));
    let content_type = part_content_type(part);
    let data = part_content_bytes(part);

    Ok(AttachmentBlob {
        data,
        filename,
        content_type,
    })
}

/// List IMAP folders on the account.
pub async fn list_folders(account: &EmailAccount) -> Result<Vec<String>, EmailError> {
    let mut session = connect(account).await?;
    let mut folders: Vec<String> = Vec::new();
    {
        let mut list = session
            .list(Some(""), Some("*"))
            .await
            .map_err(|e| EmailError::Upstream(format!("LIST: {}", e)))?;
        while let Some(item) = list.next().await {
            let name = item
                .map_err(|e| EmailError::Upstream(format!("LIST parse: {}", e)))?;
            folders.push(name.name().to_string());
        }
    }
    disconnect(session).await;
    Ok(folders)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fetch_rfc822(session: &mut ImapSession, uid: &str) -> Result<Vec<u8>, EmailError> {
    let mut fetch_stream = session
        .fetch(uid, "(RFC822)")
        .await
        .map_err(|e| EmailError::Upstream(format!("FETCH {}: {}", uid, e)))?;

    let mut raw = Vec::new();
    while let Some(item) = fetch_stream.next().await {
        let fetch = item.map_err(|e| EmailError::Upstream(format!("FETCH parse: {}", e)))?;
        if let Some(body) = fetch.body() {
            raw = body.to_vec();
            break;
        }
    }
    // Drain the rest
    while fetch_stream.next().await.is_some() {}
    if raw.is_empty() {
        return Err(EmailError::NotFound(format!("message {} not found", uid)));
    }
    Ok(raw)
}

fn extract_headers(msg: &mail_parser::Message<'_>) -> (String, String, String, String) {
    let from = msg.from().map(format_address).unwrap_or_default();
    let to = msg.to().map(format_address).unwrap_or_default();
    let subject = msg.subject().unwrap_or("").to_string();
    let date = msg
        .date()
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    (from, to, subject, date)
}

fn format_address(addr: &mail_parser::Address<'_>) -> String {
    match addr {
        mail_parser::Address::List(list) => list
            .iter()
            .filter_map(|a| a.address.as_deref())
            .collect::<Vec<_>>()
            .join(", "),
        mail_parser::Address::Group(groups) => groups
            .iter()
            .flat_map(|g| g.addresses.iter())
            .filter_map(|a| a.address.as_deref())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn part_content_type(part: &mail_parser::MessagePart<'_>) -> String {
    if let Some(ct) = part.content_type() {
        let ty = ct.ctype();
        let mut s = String::from(ty);
        if let Some(sub) = ct.subtype() {
            s.push('/');
            s.push_str(sub);
        }
        if !s.is_empty() {
            return s;
        }
    }
    "application/octet-stream".to_string()
}

fn part_content_bytes(part: &mail_parser::MessagePart<'_>) -> Vec<u8> {
    match &part.body {
        PartType::Text(s) | PartType::Html(s) => s.as_bytes().to_vec(),
        PartType::Binary(b) | PartType::InlineBinary(b) => b.to_vec(),
        // Nested RFC822 message as attachment — serialize headers+body
        PartType::Message(_) | PartType::Multipart(_) => Vec::new(),
    }
}

fn part_content_len(part: &mail_parser::MessagePart<'_>) -> usize {
    match &part.body {
        PartType::Text(s) | PartType::Html(s) => s.len(),
        PartType::Binary(b) | PartType::InlineBinary(b) => b.len(),
        PartType::Message(_) | PartType::Multipart(_) => 0,
    }
}

/// Truncate a string to at most `max` chars (not bytes — chars), so we
/// never split a multi-byte UTF-8 sequence.
fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn escape_imap_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
