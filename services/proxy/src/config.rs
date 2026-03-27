//! Hot-reloadable proxy configuration.
//!
//! Warden pushes config updates via HTTP; the proxy swaps atomically
//! using `arc-swap` so readers (hot path) never block.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use arc_swap::ArcSwap;
use secrecy::SecretString;
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
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub rate_limit_rpm: Option<u32>,
    #[serde(default)]
    pub credential_header: Option<String>,
    #[serde(default)]
    pub credential_format: Option<String>,
    #[serde(default)]
    pub credential_value: Option<String>,
}

/// Full proxy configuration, pushed by warden.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// Allowed domains with their policies.
    #[serde(default)]
    pub domains: Vec<DomainPolicy>,

    /// Pre-computed: domain name → index into `domains`.
    #[serde(skip)]
    pub domain_index: HashMap<String, usize>,

    /// Pre-computed: set of allowed domain names for fast lookup.
    #[serde(skip)]
    pub allowed_domains: HashSet<String>,

    /// Pre-computed: `{alias}.devbox.local` → index into `domains`.
    #[serde(skip)]
    pub alias_index: HashMap<String, usize>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            domain_index: HashMap::new(),
            allowed_domains: HashSet::new(),
            alias_index: HashMap::new(),
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
