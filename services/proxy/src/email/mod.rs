//! Email module: generic IMAP/SMTP password auth with policy enforcement.
//!
//! Implements the `email.devbox.local` HTTP API that cells use to send and
//! read mail.  Requires `PROXY_MODE=rust` (cagent-proxy is the only email
//! backend; the legacy Python service has been removed).
//! OAuth2 (Gmail/Outlook) is intentionally out of scope here.

pub mod config;
pub mod handler;
mod imap;
pub mod policy;
mod smtp;

pub use config::EmailAccount;
