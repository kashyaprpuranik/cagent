//! Email module: generic IMAP/SMTP password auth with policy enforcement.
//!
//! Replaces the legacy `services/email_proxy/` Python service in rust mode.
//! OAuth2 (Gmail/Outlook) is intentionally out of scope here.

pub mod config;
pub mod handler;
mod imap;
pub mod policy;
mod smtp;

pub use config::EmailAccount;
