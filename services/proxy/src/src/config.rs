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
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            domain_index: HashMap::new(),
            allowed_domains: HashSet::new(),
        }
    }
}

impl ProxyConfig {
    /// Build indexes after deserialization.
    pub fn build_indexes(mut self) -> Self {
        self.domain_index.clear();
        self.allowed_domains.clear();
        for (i, policy) in self.domains.iter().enumerate() {
            let domain = policy.domain.to_lowercase();
            self.domain_index.insert(domain.clone(), i);
            self.allowed_domains.insert(domain);
        }
        self
    }

    /// Check if a domain is allowed.
    pub fn is_allowed(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.allowed_domains.contains(&lower) {
            return true;
        }
        // Check wildcard: *.example.com matches sub.example.com
        if let Some(dot_pos) = lower.find('.') {
            let wildcard = format!("*.{}", &lower[dot_pos + 1..]);
            return self.allowed_domains.contains(&wildcard);
        }
        false
    }

    /// Get the policy for a domain.
    pub fn get_policy(&self, domain: &str) -> Option<&DomainPolicy> {
        let lower = domain.to_lowercase();
        if let Some(&idx) = self.domain_index.get(&lower) {
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
