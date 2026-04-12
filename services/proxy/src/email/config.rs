//! Email account configuration pushed by warden.
//!
//! Generic IMAP/SMTP password auth only — OAuth2 (Gmail/Outlook) is
//! intentionally out of scope for this port of the legacy Python service.

use serde::{Deserialize, Serialize};

/// Per-account sender/recipient allowlists and hourly rate limits.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailPolicy {
    /// Wildcard patterns for allowed recipient addresses (e.g. `*@company.com`).
    /// `["*"]` means any recipient is allowed.  Empty list blocks everything.
    #[serde(default = "default_star")]
    pub allowed_recipients: Vec<String>,

    /// Wildcard patterns for allowed sender addresses on read operations.
    /// Messages from non-matching senders are filtered out of inbox listings
    /// and return 403 on get_message.
    #[serde(default = "default_star")]
    pub allowed_senders: Vec<String>,

    /// Maximum /send calls per hour per account.  Enforced by a token bucket.
    #[serde(default = "default_sends_per_hour")]
    pub sends_per_hour: u32,

    /// Maximum /inbox + /message + /folders calls per hour per account.
    #[serde(default = "default_reads_per_hour")]
    pub reads_per_hour: u32,
}

impl Default for EmailPolicy {
    fn default() -> Self {
        Self {
            allowed_recipients: vec!["*".to_string()],
            allowed_senders: vec!["*".to_string()],
            sends_per_hour: default_sends_per_hour(),
            reads_per_hour: default_reads_per_hour(),
        }
    }
}

fn default_star() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_sends_per_hour() -> u32 {
    50
}

fn default_reads_per_hour() -> u32 {
    200
}

/// Credential for a generic IMAP/SMTP account.  No OAuth2 fields — Gmail
/// and Outlook providers are deferred.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailCredential {
    /// IMAP/SMTP password.
    #[serde(default)]
    pub password: String,
    /// Optional SMTP username override (defaults to the account email).
    #[serde(default)]
    pub smtp_username: String,
}

impl Default for EmailCredential {
    fn default() -> Self {
        Self {
            password: String::new(),
            smtp_username: String::new(),
        }
    }
}

/// Email account definition pushed by warden as part of ProxyConfig.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailAccount {
    /// Unique account identifier used in API paths (e.g. `work-mail`).
    pub name: String,
    /// Account email address used as From: on outgoing mail and as the
    /// default IMAP/SMTP login name.
    pub email: String,
    pub imap_server: String,
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    pub smtp_server: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub credential: EmailCredential,
    #[serde(default)]
    pub policy: EmailPolicy,
}

fn default_imap_port() -> u16 {
    993
}

fn default_smtp_port() -> u16 {
    587
}

impl EmailAccount {
    /// Username to present on IMAP/SMTP LOGIN.  Defaults to the email address.
    pub fn login_username(&self) -> &str {
        if self.credential.smtp_username.is_empty() {
            &self.email
        } else {
            &self.credential.smtp_username
        }
    }
}
