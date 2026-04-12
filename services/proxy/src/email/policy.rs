//! Policy enforcement for the email API.
//!
//! Mirrors the Python legacy service's policy.py:
//!   - check_recipients_allowed: returns disallowed list (empty = ok)
//!   - check_sender_allowed: bool
//!   - RateLimiter: per-account-action token bucket, rate = per/3600 tokens/sec,
//!     burst = max(1, per/10)

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::LazyLock;
use std::time::Instant;

use wildmatch::WildMatch;

use crate::email::config::EmailPolicy;

/// Normalize an address for matching: lowercase + trim whitespace.
/// Strips display names ("Name <addr@x>") — matches only the bare address.
fn normalize_addr(addr: &str) -> String {
    let trimmed = addr.trim();
    // "Name <addr@x>" → "addr@x"
    if let (Some(start), Some(end)) = (trimmed.rfind('<'), trimmed.rfind('>')) {
        if start < end {
            return trimmed[start + 1..end].trim().to_lowercase();
        }
    }
    trimmed.to_lowercase()
}

/// Match a single address against a list of wildcard patterns.
fn matches_any(addr: &str, patterns: &[String]) -> bool {
    if patterns.iter().any(|p| p == "*") {
        return true;
    }
    let addr_lower = normalize_addr(addr);
    patterns
        .iter()
        .any(|p| WildMatch::new(&p.to_lowercase()).matches(&addr_lower))
}

/// Check recipients against `allowed_recipients`.
/// Returns the list of addresses that violate the policy (empty = all OK).
pub fn check_recipients_allowed(recipients: &[String], policy: &EmailPolicy) -> Vec<String> {
    if policy.allowed_recipients.iter().any(|p| p == "*") {
        return Vec::new();
    }
    recipients
        .iter()
        .filter(|addr| !matches_any(addr, &policy.allowed_recipients))
        .cloned()
        .collect()
}

/// Check if a sender matches `allowed_senders`.
pub fn check_sender_allowed(sender: &str, policy: &EmailPolicy) -> bool {
    matches_any(sender, &policy.allowed_senders)
}

// ---------------------------------------------------------------------------
// Per-account-action token bucket rate limiter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateAction {
    Send,
    Read,
}

impl RateAction {
    fn as_key(&self) -> &'static str {
        match self {
            RateAction::Send => "send",
            RateAction::Read => "read",
        }
    }
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(per_hour: u32) -> Self {
        let per_sec = per_hour as f64 / 3600.0;
        let burst = ((per_hour / 10).max(1)) as f64;
        Self {
            tokens: burst,
            max_tokens: burst,
            refill_rate: per_sec,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self, per_hour: u32) -> bool {
        // Re-derive rate/burst in case config changed
        let per_sec = per_hour as f64 / 3600.0;
        let burst = ((per_hour / 10).max(1)) as f64;
        self.refill_rate = per_sec;
        self.max_tokens = burst;

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

static BUCKETS: LazyLock<Mutex<HashMap<String, TokenBucket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Check the per-account-action rate limit and consume a token if allowed.
/// Returns true if the request is permitted.
pub fn check_rate_limit(account_name: &str, action: RateAction, policy: &EmailPolicy) -> bool {
    let per_hour = match action {
        RateAction::Send => policy.sends_per_hour,
        RateAction::Read => policy.reads_per_hour,
    };
    if per_hour == 0 {
        return false;
    }
    let key = format!("{}:{}", account_name, action.as_key());
    let mut buckets = BUCKETS.lock().unwrap();
    let bucket = buckets.entry(key).or_insert_with(|| TokenBucket::new(per_hour));
    bucket.try_acquire(per_hour)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(recips: &[&str], senders: &[&str]) -> EmailPolicy {
        EmailPolicy {
            allowed_recipients: recips.iter().map(|s| s.to_string()).collect(),
            allowed_senders: senders.iter().map(|s| s.to_string()).collect(),
            sends_per_hour: 100,
            reads_per_hour: 100,
        }
    }

    #[test]
    fn wildcard_allows_all() {
        let p = policy(&["*"], &["*"]);
        assert!(check_recipients_allowed(&["a@x.com".into(), "b@y.com".into()], &p).is_empty());
        assert!(check_sender_allowed("a@x.com", &p));
    }

    #[test]
    fn exact_match() {
        let p = policy(&["admin@company.com"], &["alerts@company.com"]);
        assert_eq!(
            check_recipients_allowed(&["admin@company.com".into()], &p),
            Vec::<String>::new(),
        );
        assert_eq!(
            check_recipients_allowed(&["other@company.com".into()], &p),
            vec!["other@company.com".to_string()],
        );
        assert!(check_sender_allowed("alerts@company.com", &p));
        assert!(!check_sender_allowed("spam@example.com", &p));
    }

    #[test]
    fn domain_wildcard() {
        let p = policy(&["*@company.com"], &["*@company.com"]);
        assert!(check_recipients_allowed(&["a@company.com".into()], &p).is_empty());
        assert_eq!(
            check_recipients_allowed(&["a@other.com".into()], &p),
            vec!["a@other.com".to_string()],
        );
        assert!(check_sender_allowed("a@company.com", &p));
        assert!(!check_sender_allowed("a@other.com", &p));
    }

    #[test]
    fn strip_display_name() {
        let p = policy(&["*@company.com"], &["*@company.com"]);
        assert!(check_sender_allowed("Alice <alice@company.com>", &p));
        // display name must not bypass policy
        assert!(!check_sender_allowed("Legit <evil@attacker.com>", &p));
    }

    #[test]
    fn case_insensitive() {
        let p = policy(&["Admin@Company.COM"], &["*"]);
        assert!(check_recipients_allowed(&["ADMIN@COMPANY.com".into()], &p).is_empty());
    }

    #[test]
    fn empty_list_blocks_all() {
        let p = policy(&[], &[]);
        assert_eq!(
            check_recipients_allowed(&["anyone@anywhere.com".into()], &p),
            vec!["anyone@anywhere.com".to_string()],
        );
        assert!(!check_sender_allowed("anyone@anywhere.com", &p));
    }

    #[test]
    fn mixed_recipients() {
        let p = policy(&["*@company.com", "partner@external.com"], &["*"]);
        let disallowed = check_recipients_allowed(
            &[
                "alice@company.com".into(),
                "partner@external.com".into(),
                "random@other.com".into(),
            ],
            &p,
        );
        assert_eq!(disallowed, vec!["random@other.com".to_string()]);
    }

    #[test]
    fn rate_limit_consumes_tokens() {
        let p = EmailPolicy {
            allowed_recipients: vec!["*".into()],
            allowed_senders: vec!["*".into()],
            sends_per_hour: 20,   // burst = 2
            reads_per_hour: 100,
        };
        // Use unique account name so buckets don't collide with other tests
        let acct = format!("rl-test-{}", std::process::id());
        assert!(check_rate_limit(&acct, RateAction::Send, &p));
        assert!(check_rate_limit(&acct, RateAction::Send, &p));
        // Third call within the same tick should fail — bucket empty
        assert!(!check_rate_limit(&acct, RateAction::Send, &p));
    }

    #[test]
    fn zero_per_hour_blocks() {
        let p = EmailPolicy {
            allowed_recipients: vec!["*".into()],
            allowed_senders: vec!["*".into()],
            sends_per_hour: 0,
            reads_per_hour: 0,
        };
        let acct = format!("rl-zero-{}", std::process::id());
        assert!(!check_rate_limit(&acct, RateAction::Send, &p));
        assert!(!check_rate_limit(&acct, RateAction::Read, &p));
    }
}
