//! Hot-reloadable proxy configuration.
//!
//! Warden pushes config updates via HTTP; the proxy swaps atomically
//! using `arc-swap` so readers (hot path) never block.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Global proxy configuration, swapped atomically on config push.
pub static CONFIG: LazyLock<ArcSwap<ProxyConfig>> = LazyLock::new(|| {
    ArcSwap::from_pointee(ProxyConfig::default())
});

/// Domain policy entry from the control plane.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainPolicy {
    pub domain: String,
    /// Optional alias: creates `{alias}.devbox.local` shortcut for this domain.
    #[serde(default)]
    pub alias: Option<String>,
    /// HTTPS upstream when true (default), HTTP upstream when false.
    /// Mirrors `tls` in cagent.yaml — `tls: false` is for HTTP-only upstreams.
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub rate_limit_rpm: Option<u32>,
    /// Token bucket burst size override (defaults to rpm/6 when None).
    #[serde(default)]
    pub burst_size: Option<u32>,
    /// Per-domain upstream timeout, e.g. "30s", "120s", "5m".
    /// Falls back to DEFAULT_UPSTREAM_TIMEOUT_SECS when None or unparseable.
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub credential_header: Option<String>,
    #[serde(default)]
    pub credential_format: Option<String>,
    #[serde(default)]
    pub credential_value: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Default upstream timeout when a domain doesn't specify one.
pub const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 30;

/// Parse a duration string like "30s", "120s", "5m", "1h" into Duration.
/// Returns the default when input is None or unparseable.
pub fn parse_timeout(s: Option<&str>) -> std::time::Duration {
    let default = std::time::Duration::from_secs(DEFAULT_UPSTREAM_TIMEOUT_SECS);
    let Some(raw) = s else { return default };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return default;
    }
    // Split numeric prefix from suffix
    let (num_part, unit) = match trimmed.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
        None => (trimmed, "s"), // bare number → seconds
    };
    let n: f64 = match num_part.parse() {
        Ok(v) if v > 0.0 => v,
        _ => return default,
    };
    let secs = match unit.trim() {
        "s" | "" => n,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        "ms" => n / 1000.0,
        _ => return default,
    };
    if secs <= 0.0 || !secs.is_finite() {
        return default;
    }
    std::time::Duration::from_secs_f64(secs)
}

/// Full proxy configuration, pushed by warden.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Allowed domains with their policies.
    #[serde(default)]
    pub domains: Vec<DomainPolicy>,

    /// DLP (Data Loss Prevention) configuration.
    #[serde(default)]
    pub dlp: crate::dlp::DlpConfig,

    /// Email accounts for the in-process IMAP/SMTP handler.  Generic
    /// password auth only — OAuth2 accounts are rejected at config push
    /// time (warden filters them out before sending).
    #[serde(default)]
    pub email_accounts: Vec<crate::email::EmailAccount>,

    /// Pre-computed: domain name → index into `domains`.
    #[serde(skip)]
    pub domain_index: HashMap<String, usize>,

    /// Pre-computed: set of allowed domain names for fast lookup.
    #[serde(skip)]
    pub allowed_domains: HashSet<String>,

    /// Pre-computed: `{alias}.devbox.local` → index into `domains`.
    #[serde(skip)]
    pub alias_index: HashMap<String, usize>,

    /// Pre-compiled custom DLP patterns (compiled once per config push, not per request).
    #[serde(skip)]
    pub compiled_custom_patterns: Vec<crate::dlp::CompiledPattern>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            dlp: crate::dlp::DlpConfig::default(),
            email_accounts: Vec::new(),
            domain_index: HashMap::new(),
            allowed_domains: HashSet::new(),
            alias_index: HashMap::new(),
            compiled_custom_patterns: Vec::new(),
        }
    }
}

impl ProxyConfig {
    /// Build indexes after deserialization.
    pub fn build_indexes(mut self) -> Self {
        self.domain_index.clear();
        self.allowed_domains.clear();
        self.alias_index.clear();
        for (i, policy) in self.domains.iter().enumerate() {
            let domain = policy.domain.to_lowercase();
            self.domain_index.insert(domain.clone(), i);
            self.allowed_domains.insert(domain);
            // Build alias index: "openai.devbox.local" → index
            if let Some(alias) = &policy.alias {
                let alias_domain = format!("{}.devbox.local", alias.to_lowercase());
                self.alias_index.insert(alias_domain, i);
            }
        }
        // Pre-compile custom DLP patterns once per config push
        self.compiled_custom_patterns = crate::dlp::compile_pattern_list(&self.dlp.custom_patterns);
        self
    }

    /// Check if a domain is allowed (including devbox.local aliases).
    pub fn is_allowed(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.allowed_domains.contains(&lower) {
            return true;
        }
        // Check devbox.local alias
        if self.alias_index.contains_key(&lower) {
            return true;
        }
        // Check wildcard: *.example.com matches sub.example.com
        if let Some(dot_pos) = lower.find('.') {
            let wildcard = format!("*.{}", &lower[dot_pos + 1..]);
            return self.allowed_domains.contains(&wildcard);
        }
        false
    }

    /// Resolve a devbox.local alias to (real_domain, policy).
    /// Returns None if the domain is not an alias.
    pub fn resolve_alias(&self, domain: &str) -> Option<&DomainPolicy> {
        let lower = domain.to_lowercase();
        self.alias_index.get(&lower).map(|&idx| &self.domains[idx])
    }

    /// Return a copy of this config safe to serialize for operator display.
    ///
    /// `credential_value` on each domain is replaced with `Some("<redacted>")`
    /// when a value was configured, or left `None` otherwise.  This preserves
    /// visibility into which domains have credential injection enabled without
    /// leaking the actual secret to any infra-net peer that can reach
    /// `GET /config`.
    pub fn redacted_for_display(&self) -> ProxyConfig {
        let mut copy = self.clone();
        for policy in &mut copy.domains {
            if policy.credential_value.is_some() {
                policy.credential_value = Some("<redacted>".to_string());
            }
        }
        copy
    }

    /// Get the policy for a domain (including alias lookup).
    pub fn get_policy(&self, domain: &str) -> Option<&DomainPolicy> {
        let lower = domain.to_lowercase();
        if let Some(&idx) = self.domain_index.get(&lower) {
            return Some(&self.domains[idx]);
        }
        // Alias lookup
        if let Some(&idx) = self.alias_index.get(&lower) {
            return Some(&self.domains[idx]);
        }
        // Wildcard fallback
        if let Some(dot_pos) = lower.find('.') {
            let wildcard = format!("*.{}", &lower[dot_pos + 1..]);
            if let Some(&idx) = self.domain_index.get(&wildcard) {
                return Some(&self.domains[idx]);
            }
        }
        None
    }
}

/// Update the global config atomically.
pub fn update_config(new_config: ProxyConfig) {
    let config = new_config.build_indexes();
    CONFIG.store(std::sync::Arc::new(config));
    tracing::info!("Config updated: {} domains", CONFIG.load().domains.len());
}

// ---------------------------------------------------------------------------
// Per-domain token bucket rate limiter
// ---------------------------------------------------------------------------

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rpm: u32, burst: Option<u32>) -> Self {
        let per_sec = rpm as f64 / 60.0;
        // Burst defaults to max(rpm/6, 1) — allows short bursts without draining
        // the bucket — but the policy can override it explicitly via burst_size.
        let burst = burst
            .map(|b| b as f64)
            .unwrap_or_else(|| (rpm as f64 / 6.0).max(1.0));
        Self {
            tokens: burst,
            max_tokens: burst,
            refill_rate: per_sec,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Global rate limiter state (domain → token bucket).
static RATE_LIMITER: LazyLock<Mutex<HashMap<String, TokenBucket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Check rate limit for a domain. Returns true if the request is allowed.
///
/// `burst` is the explicit burst size from policy (None → default rpm/6).
pub fn check_rate_limit(domain: &str, rpm: u32, burst: Option<u32>) -> bool {
    let mut buckets = RATE_LIMITER.lock().unwrap();
    let bucket = buckets
        .entry(domain.to_lowercase())
        .or_insert_with(|| TokenBucket::new(rpm, burst));
    // Update bucket state if config changed (rpm or burst override)
    let per_sec = rpm as f64 / 60.0;
    let new_burst = burst
        .map(|b| b as f64)
        .unwrap_or_else(|| (rpm as f64 / 6.0).max(1.0));
    bucket.refill_rate = per_sec;
    bucket.max_tokens = new_burst;
    bucket.try_acquire()
}
