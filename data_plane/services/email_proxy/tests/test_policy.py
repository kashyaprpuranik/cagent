"""Tests for email address allowlists and rate limiting."""

import sys
import os
import time

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import EmailPolicy
from policy import check_recipients_allowed, check_sender_allowed, RateLimiter


class TestRecipientAllowlist:
    def test_wildcard_recipient_match(self):
        """*@company.com matches user@company.com"""
        policy = EmailPolicy(allowed_recipients=["*@company.com"])
        disallowed = check_recipients_allowed(["user@company.com"], policy)
        assert disallowed == []

    def test_wildcard_matches_any_user(self):
        """*@company.com matches any user at company.com"""
        policy = EmailPolicy(allowed_recipients=["*@company.com"])
        disallowed = check_recipients_allowed(
            ["alice@company.com", "bob@company.com", "test123@company.com"],
            policy,
        )
        assert disallowed == []

    def test_exact_recipient_match(self):
        """Exact email matches"""
        policy = EmailPolicy(allowed_recipients=["partner@external.com"])
        disallowed = check_recipients_allowed(["partner@external.com"], policy)
        assert disallowed == []

    def test_recipient_blocked(self):
        """Unlisted address is denied"""
        policy = EmailPolicy(allowed_recipients=["*@company.com"])
        disallowed = check_recipients_allowed(["hacker@evil.com"], policy)
        assert disallowed == ["hacker@evil.com"]

    def test_mixed_allowed_and_blocked(self):
        """Some allowed, some blocked"""
        policy = EmailPolicy(
            allowed_recipients=["*@company.com", "partner@external.com"]
        )
        disallowed = check_recipients_allowed(
            ["user@company.com", "hacker@evil.com", "partner@external.com"],
            policy,
        )
        assert disallowed == ["hacker@evil.com"]

    def test_star_allows_all(self):
        """* wildcard allows any recipient"""
        policy = EmailPolicy(allowed_recipients=["*"])
        disallowed = check_recipients_allowed(
            ["anyone@anywhere.com", "test@test.org"],
            policy,
        )
        assert disallowed == []

    def test_case_insensitive(self):
        """Matching is case-insensitive"""
        policy = EmailPolicy(allowed_recipients=["*@Company.COM"])
        disallowed = check_recipients_allowed(["user@company.com"], policy)
        assert disallowed == []

    def test_empty_recipients(self):
        """Empty list passes"""
        policy = EmailPolicy(allowed_recipients=["*@company.com"])
        disallowed = check_recipients_allowed([], policy)
        assert disallowed == []


class TestSenderAllowlist:
    def test_sender_allowed_wildcard(self):
        """* matches any sender"""
        policy = EmailPolicy(allowed_senders=["*"])
        assert check_sender_allowed("anyone@anywhere.com", policy) is True

    def test_sender_allowed_domain_wildcard(self):
        """*@domain matches senders from that domain"""
        policy = EmailPolicy(allowed_senders=["*@company.com"])
        assert check_sender_allowed("boss@company.com", policy) is True

    def test_sender_blocked(self):
        """Unlisted sender is denied"""
        policy = EmailPolicy(allowed_senders=["*@company.com"])
        assert check_sender_allowed("spammer@evil.com", policy) is False

    def test_sender_exact_match(self):
        """Exact sender match"""
        policy = EmailPolicy(allowed_senders=["specific@company.com"])
        assert check_sender_allowed("specific@company.com", policy) is True
        assert check_sender_allowed("other@company.com", policy) is False


class TestRateLimiter:
    def test_rate_limit_sends_allowed(self):
        """Sends within limit are allowed"""
        limiter = RateLimiter()
        policy = EmailPolicy(sends_per_hour=100)
        # First few sends should pass (burst bucket)
        for _ in range(5):
            assert limiter.check("test-account", "send", policy) is True

    def test_rate_limit_sends_exceeded(self):
        """Exceeding sends_per_hour is denied"""
        limiter = RateLimiter()
        policy = EmailPolicy(sends_per_hour=10)
        # Exhaust the burst bucket (burst = max(1, 10//10) = 1)
        results = []
        for _ in range(5):
            results.append(limiter.check("rate-test-send", "send", policy))
        # At least the last one should be denied
        assert False in results

    def test_rate_limit_reads_exceeded(self):
        """Exceeding reads_per_hour is denied"""
        limiter = RateLimiter()
        policy = EmailPolicy(reads_per_hour=10)
        results = []
        for _ in range(5):
            results.append(limiter.check("rate-test-read", "read", policy))
        assert False in results

    def test_rate_limit_independent_accounts(self):
        """Different accounts have independent rate limits"""
        limiter = RateLimiter()
        policy = EmailPolicy(sends_per_hour=10)
        # Exhaust account A
        for _ in range(5):
            limiter.check("account-a", "send", policy)
        # Account B should still have tokens
        assert limiter.check("account-b", "send", policy) is True

    def test_rate_limit_independent_actions(self):
        """Send and read have independent buckets"""
        limiter = RateLimiter()
        policy = EmailPolicy(sends_per_hour=10, reads_per_hour=10)
        # Use some send tokens
        limiter.check("action-test", "send", policy)
        # Read should still work
        assert limiter.check("action-test", "read", policy) is True

    def test_rate_limit_zero_denies_all(self):
        """Zero rate limit denies everything"""
        limiter = RateLimiter()
        policy = EmailPolicy(sends_per_hour=0)
        assert limiter.check("zero-test", "send", policy) is False
