"""
Policy enforcement - address allowlists and rate limiting.

Uses fnmatch-style patterns for email address matching and
in-memory token bucket for rate limiting.
"""

import fnmatch
import logging
import time

from config import EmailPolicy

logger = logging.getLogger(__name__)


def check_recipients_allowed(recipients: list[str], policy: EmailPolicy) -> list[str]:
    """Check recipients against allowlist. Returns list of disallowed addresses (empty = all OK)."""
    if "*" in policy.allowed_recipients:
        return []

    disallowed = []
    for addr in recipients:
        addr_lower = addr.lower().strip()
        if not any(fnmatch.fnmatch(addr_lower, pattern.lower()) for pattern in policy.allowed_recipients):
            disallowed.append(addr)
    return disallowed


def check_sender_allowed(sender: str, policy: EmailPolicy) -> bool:
    """Check if a sender matches the allowed_senders policy."""
    if "*" in policy.allowed_senders:
        return True
    sender_lower = sender.lower().strip()
    return any(fnmatch.fnmatch(sender_lower, pattern.lower()) for pattern in policy.allowed_senders)


class RateLimiter:
    """In-memory token bucket rate limiter, per account + action."""

    def __init__(self):
        self._buckets: dict[str, dict] = {}

    def check(self, account_name: str, action: str, policy: EmailPolicy) -> bool:
        """Check if action is allowed under rate limit. Returns True if allowed."""
        if action == "send":
            max_per_hour = policy.sends_per_hour
        elif action == "read":
            max_per_hour = policy.reads_per_hour
        else:
            return True

        if max_per_hour <= 0:
            return False

        key = f"{account_name}:{action}"
        now = time.monotonic()

        bucket = self._buckets.get(key)
        if bucket is None:
            # Start with a full bucket (burst = max_per_hour for simplicity, capped at 1/10th)
            burst = max(1, max_per_hour // 10)
            bucket = {"tokens": float(burst), "last_refill": now, "rate": max_per_hour / 3600.0, "burst": burst}
            self._buckets[key] = bucket

        # Refill tokens
        elapsed = now - bucket["last_refill"]
        new_tokens = elapsed * bucket["rate"]
        bucket["tokens"] = min(bucket["burst"], bucket["tokens"] + new_tokens)
        bucket["last_refill"] = now

        if bucket["tokens"] >= 1.0:
            bucket["tokens"] -= 1.0
            return True

        logger.warning(f"Rate limit exceeded for {key}")
        return False


# Global rate limiter instance
rate_limiter = RateLimiter()
