//! DLP (Data Loss Prevention) body scanning.
//!
//! Scans request bodies for sensitive data patterns (API keys, secrets, PII).
//! Supports three modes: log (warn only), block (return 403), redact (replace matches).

use std::sync::LazyLock;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Maximum body size to scan (1 MB, matches legacy mitmproxy config).
const MAX_BODY_SCAN_BYTES: usize = 1_048_576;

/// Built-in DLP patterns (matches legacy dlp_addon.py).
static DEFAULT_PATTERNS: LazyLock<Vec<DlpPattern>> = LazyLock::new(|| {
    vec![
        DlpPattern::new("aws_access_key", r"AKIA[0-9A-Z]{16}", None),
        DlpPattern::new("github_token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}", None),
        DlpPattern::new("openai_api_key", r"sk-[A-Za-z0-9_\-]{20,}", None),
        DlpPattern::new("anthropic_api_key", r"sk-ant-[A-Za-z0-9_\-]{20,}", None),
        DlpPattern::new("generic_api_key", r#"(?i)(?:api_key|apikey|api-key|access_token|auth_token|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9_\-/.]{20,}['"]?"#, None),
        DlpPattern::new("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", None),
        DlpPattern::new("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", None),
        DlpPattern::new("connection_string", r#"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'"]{10,}"#, None),
        DlpPattern::new("ssn", r"\b\d{3}-\d{2}-\d{4}\b", None),
        DlpPattern::new("credit_card", r"\b(?:\d{4}[- ]?){3}\d{4}\b", None),
        DlpPattern::new("email_bulk", r"[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", Some(5)),
        DlpPattern::new("phone_bulk", r"\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", Some(5)),
    ]
});

/// Aho-Corasick prefixes for fast pre-filtering (only scan regex if prefix matches).
static PREFIX_MATCHER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let prefixes = &[
        "AKIA",           // aws_access_key
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", // github_token
        "sk-",            // openai_api_key, anthropic_api_key
        "api_key", "apikey", "api-key", "access_token", "auth_token", "secret_key", // generic
        "-----BEGIN",     // private_key
        "eyJ",            // jwt
        "mongodb://", "mongodb+srv://", "postgres://", "postgresql://", "mysql://", "redis://", "amqp://", // connection_string
    ];
    AhoCorasick::new(prefixes).expect("invalid aho-corasick patterns")
});

/// Base64 blob regex for detecting encoded secrets.
static BASE64_BLOB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9+/=]{32,}").expect("invalid base64 regex")
});

/// A DLP pattern definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
    #[serde(default)]
    pub threshold: Option<usize>,
}

impl DlpPattern {
    fn new(name: &str, regex: &str, threshold: Option<usize>) -> Self {
        Self {
            name: name.to_string(),
            regex: regex.to_string(),
            threshold,
        }
    }
}

/// DLP configuration, pushed as part of ProxyConfig.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DlpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dlp_mode")]
    pub mode: String,
    #[serde(default)]
    pub skip_domains: Vec<String>,
    #[serde(default)]
    pub custom_patterns: Vec<DlpPattern>,
}

fn default_dlp_mode() -> String {
    "log".to_string()
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "log".to_string(),
            skip_domains: Vec::new(),
            custom_patterns: Vec::new(),
        }
    }
}

/// A compiled pattern ready for scanning.
pub struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
    pub threshold: Option<usize>,
}

// Manual Debug impl to avoid requiring Regex: Debug
impl std::fmt::Debug for CompiledPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPattern")
            .field("name", &self.name)
            .field("threshold", &self.threshold)
            .finish()
    }
}

// Manual Clone impl since Regex doesn't implement Clone but can be reconstructed
impl Clone for CompiledPattern {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            regex: Regex::new(self.regex.as_str()).unwrap(),
            threshold: self.threshold,
        }
    }
}

/// Built-in patterns, compiled once at startup.
static COMPILED_DEFAULTS: LazyLock<Vec<CompiledPattern>> = LazyLock::new(|| {
    compile_pattern_list(&DEFAULT_PATTERNS)
});

/// A DLP finding.
pub struct DlpFinding {
    pub pattern: String,
    pub snippet: String, // first 12 chars of match
}

/// Scan result from DLP.
pub enum DlpAction {
    /// No findings or DLP disabled.
    Allow,
    /// Findings detected, mode is "log" — proceed but log.
    Log(Vec<DlpFinding>),
    /// Findings detected, mode is "block" — return 403.
    Block(Vec<DlpFinding>),
    /// Findings detected, mode is "redact" — use redacted body.
    Redact(Vec<DlpFinding>, Vec<u8>),
}

/// Scan a request body for DLP violations.
pub fn scan_body(body: &[u8], domain: &str) -> DlpAction {
    let config = crate::config::CONFIG.load();
    let dlp = &config.dlp;

    if !dlp.enabled {
        return DlpAction::Allow;
    }

    // Skip domains
    let domain_lower = domain.to_lowercase();
    if dlp.skip_domains.iter().any(|d| d.eq_ignore_ascii_case(&domain_lower)) {
        return DlpAction::Allow;
    }

    // Truncate to max scan size
    let scan_bytes = &body[..body.len().min(MAX_BODY_SCAN_BYTES)];

    // Try to interpret as UTF-8 text
    let text = match std::str::from_utf8(scan_bytes) {
        Ok(s) => s,
        Err(_) => return DlpAction::Allow, // binary body, skip
    };

    // Use pre-compiled built-in patterns + config's pre-compiled custom patterns.
    // Both are compiled once (at startup / config push), not per request.
    let defaults = &*COMPILED_DEFAULTS;
    let custom = &config.compiled_custom_patterns;

    // Fast pre-filter: skip full regex scan if no prefix matches
    let has_prefix = PREFIX_MATCHER.is_match(text);

    // Scan plaintext
    let mut findings = Vec::new();
    if has_prefix || !custom.is_empty() {
        scan_text(text, defaults, &mut findings);
        scan_text(text, custom, &mut findings);
    }

    // Scan for PII patterns (SSN, credit card, email/phone bulk) — no prefix needed
    scan_pii(text, defaults, &mut findings);
    scan_pii(text, custom, &mut findings);

    // Base64 scan
    scan_base64(text, defaults, &mut findings);
    scan_base64(text, custom, &mut findings);

    if findings.is_empty() {
        return DlpAction::Allow;
    }

    match dlp.mode.as_str() {
        "block" => DlpAction::Block(findings),
        "redact" => {
            let mut redacted = redact_text(text, defaults);
            redacted = redact_text(&redacted, custom);
            DlpAction::Redact(findings, redacted.into_bytes())
        }
        _ => DlpAction::Log(findings), // "log" or unknown
    }
}

/// Compile a list of DLP pattern definitions into ready-to-use compiled patterns.
/// Called once for built-in patterns (at startup) and once per config push for custom patterns.
pub fn compile_pattern_list(patterns: &[DlpPattern]) -> Vec<CompiledPattern> {
    let mut compiled = Vec::new();
    for p in patterns {
        match Regex::new(&p.regex) {
            Ok(re) => compiled.push(CompiledPattern {
                name: p.name.clone(),
                regex: re,
                threshold: p.threshold,
            }),
            Err(e) => tracing::warn!(pattern = %p.name, error = %e, "invalid DLP pattern"),
        }
    }
    compiled
}

fn scan_text(text: &str, patterns: &[CompiledPattern], findings: &mut Vec<DlpFinding>) {
    for p in patterns {
        if p.threshold.is_some() {
            continue; // threshold patterns handled in scan_pii
        }
        if let Some(m) = p.regex.find(text) {
            let snippet = &m.as_str()[..m.as_str().len().min(12)];
            findings.push(DlpFinding {
                pattern: p.name.clone(),
                snippet: snippet.to_string(),
            });
        }
    }
}

fn scan_pii(text: &str, patterns: &[CompiledPattern], findings: &mut Vec<DlpFinding>) {
    for p in patterns {
        if let Some(threshold) = p.threshold {
            let count = p.regex.find_iter(text).count();
            if count >= threshold {
                findings.push(DlpFinding {
                    pattern: p.name.clone(),
                    snippet: format!("{} instances", count),
                });
            }
        }
    }
}

fn scan_base64(text: &str, patterns: &[CompiledPattern], findings: &mut Vec<DlpFinding>) {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    for blob_match in BASE64_BLOB_RE.find_iter(text) {
        let blob = blob_match.as_str().trim();
        if blob.len() < 32 {
            continue;
        }
        if let Ok(decoded_bytes) = engine.decode(blob) {
            if let Ok(decoded) = std::str::from_utf8(&decoded_bytes) {
                // Scan decoded content against all patterns
                for p in patterns {
                    if p.threshold.is_some() {
                        continue;
                    }
                    if let Some(m) = p.regex.find(decoded) {
                        let snippet = &m.as_str()[..m.as_str().len().min(12)];
                        findings.push(DlpFinding {
                            pattern: format!("base64:{}", p.name),
                            snippet: snippet.to_string(),
                        });
                    }
                }
            }
        }
    }
}

fn redact_text(text: &str, patterns: &[CompiledPattern]) -> String {
    let mut result = text.to_string();
    for p in patterns {
        if let Some(threshold) = p.threshold {
            if p.regex.find_iter(&result).count() >= threshold {
                result = p.regex.replace_all(&result, "[REDACTED]").to_string();
            }
        } else {
            result = p.regex.replace_all(&result, "[REDACTED]").to_string();
        }
    }
    result
}

/// Emit a structured DLP violation event in the format Vector's transform
/// expects: `event=dlp_violation` plus host/path/method/mode/findings.
/// Vector picks this up via the Docker logs source and classifies it as
/// `log_type:dlp_violation` regardless of which proxy emitted it, so the
/// DLP analytics widgets populate in both legacy and rust modes.
pub fn emit_violation(
    method: &str,
    host: &str,
    path: &str,
    findings: &[DlpFinding],
) {
    let dlp = &crate::config::CONFIG.load().dlp;
    let mode = dlp.mode.as_str();
    // Build a JSON array of {pattern, snippet} so Vector can extract
    // dlp_pattern from the first finding (matches legacy mitmproxy schema).
    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "pattern": f.pattern,
                "snippet": f.snippet,
            })
        })
        .collect();
    let findings_str = serde_json::to_string(&findings_json).unwrap_or_else(|_| "[]".to_string());
    tracing::warn!(
        event = "dlp_violation",
        method = method,
        host = host,
        path = path,
        mode = mode,
        findings = %findings_str,
        "DLP violation"
    );
}
