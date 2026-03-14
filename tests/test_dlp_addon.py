"""
Tests for the DLP (secret detection) mitmproxy addon.

Verifies pattern detection, mode behavior, skip domains,
base64 decoding, and body size truncation.
"""

import base64
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Mock mitmproxy before importing the addon (not installed in test env)
# ---------------------------------------------------------------------------
_mock_http = types.ModuleType("mitmproxy.http")


class _MockResponse:
    """Minimal stand-in for mitmproxy.http.Response."""

    def __init__(self, status_code, content, headers):
        self.status_code = status_code
        self.content = content
        self.headers = headers

    @staticmethod
    def make(status_code, content, headers):
        return _MockResponse(status_code, content, headers)


_mock_http.HTTPFlow = MagicMock  # type annotations only
_mock_http.Response = _MockResponse

_mock_mitmproxy = types.ModuleType("mitmproxy")
_mock_mitmproxy.http = _mock_http  # type: ignore[attr-defined]
sys.modules["mitmproxy"] = _mock_mitmproxy
sys.modules["mitmproxy.http"] = _mock_http

# Now safe to import
MITM_DIR = Path(__file__).resolve().parent.parent / "configs" / "mitm"
sys.path.insert(0, str(MITM_DIR))

from dlp_addon import (  # noqa: E402
    MAX_BODY_SCAN_BYTES,
    DLPAddon,
    _compile_custom_patterns,
    _load_config,
    _redact_text,
    _scan_text,
    _try_base64_decode,
)

# Hardcoded test patterns — must NOT depend on the live dlp_config.json which
# warden may overwrite at runtime when running in connected mode.
_DEFAULT_RAW = [
    {"name": "aws_access_key", "regex": "AKIA[0-9A-Z]{16}"},
    {"name": "github_token", "regex": "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"},
    {"name": "openai_api_key", "regex": "sk-[A-Za-z0-9_-]{20,}"},
    {"name": "anthropic_api_key", "regex": "sk-ant-[A-Za-z0-9_-]{20,}"},
    {"name": "private_key", "regex": "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"},
    {"name": "jwt", "regex": "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"},
    {"name": "generic_api_key", "regex": "(?i)(?:api_key|apikey|api-key|access_token|auth_token|secret_key)[\\s]*[=:]\\s*['\"]?[A-Za-z0-9_\\-/.]{20,}['\"]?"},
    {"name": "connection_string", "regex": "(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\\s'\"]{10,}"},
    {"name": "ssn", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b"},
    {"name": "credit_card", "regex": "\\b(?:\\d{4}[- ]?){3}\\d{4}\\b"},
    {"name": "email_bulk", "regex": "[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+", "threshold": 5},
    {"name": "phone_bulk", "regex": "\\+?1?[-.\\s]?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}", "threshold": 5},
]
_DEFAULT_COMPILED = _compile_custom_patterns(_DEFAULT_RAW)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(body="", host="example.com", method="POST", path="/api"):
    """Build a minimal mock HTTPFlow for testing."""
    flow = MagicMock()
    flow.request.method = method
    flow.request.path = path
    flow.request.pretty_host = host
    flow.request.headers = {"Host": host}
    flow.request.get_text.return_value = body
    flow.response = None
    return flow


def _make_addon(enabled=True, mode="log", skip_domains=None, custom_patterns=None):
    """Build a DLPAddon with the given config (no file needed).

    custom_patterns defaults to the shipped default patterns.
    """
    addon = DLPAddon.__new__(DLPAddon)
    addon.config = {
        "enabled": enabled,
        "mode": mode,
        "skip_domains": skip_domains or [],
        "custom_patterns": custom_patterns if custom_patterns is not None else list(_DEFAULT_RAW),
    }
    addon._patterns = _compile_custom_patterns(addon.config["custom_patterns"])
    return addon


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestConfigLoading:

    def test_load_valid_config(self, tmp_path):
        cfg_file = tmp_path / "dlp_config.json"
        cfg_file.write_text(json.dumps({
            "enabled": True,
            "mode": "block",
            "skip_domains": ["a.com"],
        }))
        cfg = _load_config(cfg_file)
        assert cfg["enabled"] is True
        assert cfg["mode"] == "block"
        assert cfg["skip_domains"] == ["a.com"]

    def test_load_missing_file_returns_defaults(self, tmp_path):
        cfg = _load_config(tmp_path / "nonexistent.json")
        assert cfg["enabled"] is False
        assert cfg["mode"] == "log"
        assert cfg["skip_domains"] == []

    def test_load_invalid_json_returns_defaults(self, tmp_path):
        cfg_file = tmp_path / "bad.json"
        cfg_file.write_text("NOT JSON")
        cfg = _load_config(cfg_file)
        assert cfg["enabled"] is False

    def test_load_invalid_mode_defaults_to_log(self, tmp_path):
        cfg_file = tmp_path / "dlp_config.json"
        cfg_file.write_text(json.dumps({"enabled": True, "mode": "destroy"}))
        cfg = _load_config(cfg_file)
        assert cfg["mode"] == "log"

    def test_load_config_with_custom_patterns(self, tmp_path):
        cfg_file = tmp_path / "dlp_config.json"
        cfg_file.write_text(json.dumps({
            "enabled": True,
            "mode": "log",
            "custom_patterns": [
                {"name": "test_pat", "regex": "TEST_[A-Z]+", "threshold": 3},
            ],
        }))
        cfg = _load_config(cfg_file)
        assert len(cfg["custom_patterns"]) == 1
        assert cfg["custom_patterns"][0]["threshold"] == 3


# ---------------------------------------------------------------------------
# Pattern detection
# ---------------------------------------------------------------------------

class TestPatternDetection:

    def test_aws_access_key(self):
        text = "key=AKIAIOSFODNN7EXAMPLE"
        findings = _scan_text(text, patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "aws_access_key" in names

    def test_github_token(self):
        token = "ghp_" + "A" * 36
        findings = _scan_text(f"token={token}", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "github_token" in names

    def test_openai_api_key(self):
        findings = _scan_text("Authorization: Bearer sk-abc123def456ghi789jkl012", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "openai_api_key" in names

    def test_anthropic_api_key(self):
        findings = _scan_text("key=sk-ant-abc123def456ghi789jkl012", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "anthropic_api_key" in names

    def test_private_key(self):
        findings = _scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "private_key" in names

    def test_ec_private_key(self):
        findings = _scan_text("-----BEGIN EC PRIVATE KEY-----", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "private_key" in names

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = _scan_text(jwt, patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "jwt" in names

    def test_generic_api_key(self):
        findings = _scan_text('api_key = "abcdefghij1234567890xy"', patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "generic_api_key" in names

    def test_connection_string_postgres(self):
        findings = _scan_text("postgres://user:pass@host:5432/db", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "connection_string" in names

    def test_connection_string_mongodb(self):
        findings = _scan_text("mongodb+srv://user:pass@cluster0.abc.mongodb.net/mydb", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "connection_string" in names

    def test_no_false_positive_on_normal_text(self):
        findings = _scan_text("Hello, this is a normal request body with no secrets.", patterns=_DEFAULT_COMPILED)
        assert findings == []


# ---------------------------------------------------------------------------
# Skip domain logic
# ---------------------------------------------------------------------------

class TestSkipDomains:

    def test_skip_domain_is_not_scanned(self):
        addon = _make_addon(enabled=True, mode="block", skip_domains=["api.openai.com"])
        flow = _make_flow(body="sk-abc123def456ghi789jkl012", host="api.openai.com")
        addon.request(flow)
        assert flow.response is None

    def test_non_skip_domain_is_scanned(self):
        addon = _make_addon(enabled=True, mode="block", skip_domains=["api.openai.com"])
        flow = _make_flow(body="sk-abc123def456ghi789jkl012", host="evil.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403


# ---------------------------------------------------------------------------
# Mode behavior
# ---------------------------------------------------------------------------

class TestModeBehavior:

    def test_log_mode_does_not_block(self):
        addon = _make_addon(enabled=True, mode="log")
        flow = _make_flow(body="ghp_" + "A" * 36)
        with patch("dlp_addon._emit_log"):
            addon.request(flow)
        assert flow.response is None

    def test_block_mode_returns_403(self):
        addon = _make_addon(enabled=True, mode="block")
        flow = _make_flow(body="ghp_" + "A" * 36)
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_redact_mode_replaces_secrets(self):
        secret = "ghp_" + "A" * 36
        addon = _make_addon(enabled=True, mode="redact")
        flow = _make_flow(body=f"token={secret}&other=value")
        addon.request(flow)
        flow.request.set_text.assert_called_once()
        redacted_body = flow.request.set_text.call_args[0][0]
        assert secret not in redacted_body
        assert "[REDACTED]" in redacted_body
        assert flow.response is None


# ---------------------------------------------------------------------------
# Base64 detection
# ---------------------------------------------------------------------------

class TestBase64Detection:

    def test_base64_encoded_secret_detected(self):
        secret = "ghp_" + "A" * 36
        encoded = base64.b64encode(secret.encode()).decode()
        addon = _make_addon(enabled=True, mode="block")
        # Use newline separator so the base64 regex captures only the encoded blob
        flow = _make_flow(body=f"data:\n{encoded}")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_try_base64_decode_valid(self):
        text = base64.b64encode(b"Hello, this is a test string for base64 decoding").decode()
        result = _try_base64_decode(text)
        assert result is not None
        assert "Hello" in result

    def test_try_base64_decode_short_string(self):
        assert _try_base64_decode("abc") is None

    def test_try_base64_decode_invalid(self):
        # Characters outside the base64 alphabet cause decode failure
        assert _try_base64_decode("!" * 40) is None


# ---------------------------------------------------------------------------
# Body truncation
# ---------------------------------------------------------------------------

class TestBodyTruncation:

    def test_large_body_secret_past_limit_not_detected(self):
        addon = _make_addon(enabled=True, mode="block")
        padding = "A" * (MAX_BODY_SCAN_BYTES + 100)
        secret = "ghp_" + "B" * 36
        body = padding + secret
        flow = _make_flow(body=body)
        addon.request(flow)
        assert flow.response is None

    def test_secret_within_limit_is_detected(self):
        addon = _make_addon(enabled=True, mode="block")
        secret = "ghp_" + "B" * 36
        flow = _make_flow(body=secret)
        addon.request(flow)
        assert flow.response is not None


# ---------------------------------------------------------------------------
# Disabled mode
# ---------------------------------------------------------------------------

class TestDisabledMode:

    def test_disabled_addon_does_nothing(self):
        addon = _make_addon(enabled=False, mode="block")
        flow = _make_flow(body="ghp_" + "A" * 36)
        addon.request(flow)
        assert flow.response is None

    def test_empty_body_does_nothing(self):
        addon = _make_addon(enabled=True, mode="block")
        flow = _make_flow(body="")
        addon.request(flow)
        assert flow.response is None


# ---------------------------------------------------------------------------
# Redact helper
# ---------------------------------------------------------------------------

class TestRedactText:

    def test_redact_replaces_all_matches(self):
        secret1 = "ghp_" + "C" * 36
        secret2 = "sk-ant-DDDDDDDDDDDDDDDDDDDDDDDDDDD"
        text = f"a={secret1}&b={secret2}"
        result = _redact_text(text, patterns=_DEFAULT_COMPILED)
        assert secret1 not in result
        assert secret2 not in result
        assert "[REDACTED]" in result


# ---------------------------------------------------------------------------
# Custom patterns
# ---------------------------------------------------------------------------

class TestCustomPatterns:

    def test_custom_pattern_loaded_from_config(self, tmp_path):
        cfg_file = tmp_path / "dlp_config.json"
        cfg_file.write_text(json.dumps({
            "enabled": True,
            "mode": "log",
            "skip_domains": [],
            "custom_patterns": [
                {"name": "internal_token", "regex": r"INTERNAL_[A-Z]{16}"}
            ],
        }))
        cfg = _load_config(cfg_file)
        assert len(cfg["custom_patterns"]) == 1
        assert cfg["custom_patterns"][0]["name"] == "internal_token"

    def test_invalid_custom_regex_skipped(self):
        patterns = _compile_custom_patterns([
            {"name": "good", "regex": r"GOOD_[A-Z]+"},
            {"name": "bad", "regex": r"[invalid("},
            {"name": "also_good", "regex": r"ALSO_[A-Z]+"},
        ])
        assert len(patterns) == 2
        names = [p[0] for p in patterns]
        assert "good" in names
        assert "also_good" in names
        assert "bad" not in names

    def test_custom_pattern_detection_in_scan(self):
        patterns = _compile_custom_patterns([
            {"name": "corp_secret", "regex": r"CORP_SECRET_[A-Z0-9]{20}"},
        ])
        findings = _scan_text("data=CORP_SECRET_ABCDEFGHIJ1234567890", patterns=patterns)
        names = [f["pattern"] for f in findings]
        assert "corp_secret" in names

    def test_custom_pattern_block_mode(self):
        addon = _make_addon(
            enabled=True,
            mode="block",
            custom_patterns=[{"name": "corp_key", "regex": r"CORPKEY_[A-Z0-9]{20}"}],
        )
        flow = _make_flow(body="token=CORPKEY_ABCDEFGHIJ1234567890")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_custom_pattern_alongside_defaults(self):
        """Custom patterns combined with default patterns all work."""
        extra = [{"name": "corp_key", "regex": r"CORPKEY_[A-Z0-9]{20}"}]
        addon = _make_addon(
            enabled=True,
            mode="block",
            custom_patterns=list(_DEFAULT_RAW) + extra,
        )
        # Default pattern still works
        flow = _make_flow(body="ghp_" + "A" * 36)
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_empty_custom_patterns_no_error(self):
        patterns = _compile_custom_patterns([])
        assert patterns == []

    def test_missing_name_or_regex_skipped(self):
        patterns = _compile_custom_patterns([
            {"name": "no_regex"},
            {"regex": r"no_name"},
            {"name": "", "regex": r"empty_name"},
            {"name": "empty_regex", "regex": ""},
        ])
        assert patterns == []

    def test_threshold_pattern_compiled(self):
        patterns = _compile_custom_patterns([
            {"name": "bulk_test", "regex": r"test_\d+", "threshold": 3},
        ])
        assert len(patterns) == 1
        name, _, threshold = patterns[0]
        assert name == "bulk_test"
        assert threshold == 3

    def test_threshold_none_when_absent(self):
        patterns = _compile_custom_patterns([
            {"name": "no_threshold", "regex": r"NT_[A-Z]+"},
        ])
        assert len(patterns) == 1
        _, _, threshold = patterns[0]
        assert threshold is None

    def test_invalid_threshold_treated_as_none(self):
        patterns = _compile_custom_patterns([
            {"name": "bad_thresh", "regex": r"BT_[A-Z]+", "threshold": "not_a_number"},
        ])
        assert len(patterns) == 1
        _, _, threshold = patterns[0]
        assert threshold is None


# ---------------------------------------------------------------------------
# PII pattern detection
# ---------------------------------------------------------------------------

class TestPIIDetection:

    def test_ssn_detected(self):
        findings = _scan_text("SSN: 123-45-6789", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "ssn" in names

    def test_ssn_no_false_positive(self):
        # Phone-like number should not match SSN pattern (different format)
        findings = _scan_text("call 123-456-7890", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "ssn" not in names

    def test_credit_card_detected(self):
        findings = _scan_text("card: 4111-1111-1111-1111", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "credit_card" in names

    def test_credit_card_no_separator(self):
        findings = _scan_text("card: 4111111111111111", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "credit_card" in names

    def test_credit_card_space_separator(self):
        findings = _scan_text("card: 4111 1111 1111 1111", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "credit_card" in names

    def test_email_bulk_at_threshold(self):
        emails = " ".join(f"user{i}@example.com" for i in range(5))
        findings = _scan_text(emails, patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "email_bulk" in names

    def test_email_bulk_below_threshold(self):
        emails = " ".join(f"user{i}@example.com" for i in range(4))
        findings = _scan_text(emails, patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "email_bulk" not in names

    def test_phone_bulk_at_threshold(self):
        phones = " ".join(f"(555) 000-{i:04d}" for i in range(5))
        findings = _scan_text(phones, patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "phone_bulk" in names

    def test_phone_bulk_below_threshold(self):
        phones = " ".join(f"(555) 000-{i:04d}" for i in range(4))
        findings = _scan_text(phones, patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "phone_bulk" not in names

    def test_single_email_no_flag(self):
        findings = _scan_text("contact: admin@example.com", patterns=_DEFAULT_COMPILED)
        names = [f["pattern"] for f in findings]
        assert "email_bulk" not in names

    def test_pii_block_mode(self):
        addon = _make_addon(enabled=True, mode="block")
        flow = _make_flow(body="SSN: 123-45-6789")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403


# ---------------------------------------------------------------------------
# Selective patterns (removing patterns from config disables them)
# ---------------------------------------------------------------------------

class TestSelectivePatterns:

    def test_removing_pattern_from_config_disables_it(self):
        """Omitting a pattern from custom_patterns means it won't be detected."""
        # Use only ssn pattern, no github_token
        addon = _make_addon(
            enabled=True,
            mode="block",
            custom_patterns=[{"name": "ssn", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b"}],
        )
        flow = _make_flow(body="ghp_" + "A" * 36)
        addon.request(flow)
        # github_token not in config — should NOT block
        assert flow.response is None

    def test_empty_patterns_detects_nothing(self):
        addon = _make_addon(enabled=True, mode="block", custom_patterns=[])
        flow = _make_flow(body="ghp_" + "A" * 36 + " SSN: 123-45-6789")
        addon.request(flow)
        assert flow.response is None

    def test_subset_of_patterns_still_works(self):
        """Only secrets, no PII."""
        secrets_only = [p for p in _DEFAULT_RAW if p["name"] in ("github_token", "openai_api_key")]
        addon = _make_addon(enabled=True, mode="block", custom_patterns=secrets_only)
        # Secret detected
        flow_secret = _make_flow(body="ghp_" + "A" * 36)
        addon.request(flow_secret)
        assert flow_secret.response is not None
        # PII not detected
        flow_ssn = _make_flow(body="SSN: 123-45-6789")
        addon.request(flow_ssn)
        assert flow_ssn.response is None


# ---------------------------------------------------------------------------
# Default config ships all patterns
# ---------------------------------------------------------------------------

class TestDefaultConfig:
    """Validate the shipped dlp_config.json (reads from git HEAD, not the live file
    which warden may overwrite in connected mode)."""

    @pytest.fixture(autouse=True)
    def _load_shipped_config(self):
        """Load the committed default config from git to avoid warden overwrites."""
        import subprocess
        raw = subprocess.check_output(
            ["git", "show", "HEAD:configs/mitm/dlp_config.json"],
            cwd=MITM_DIR.parent.parent,
        )
        self.shipped_config = json.loads(raw)
        self.shipped_patterns = self.shipped_config["custom_patterns"]

    def test_shipped_config_has_all_patterns(self):
        names = [p["name"] for p in self.shipped_patterns]
        assert "aws_access_key" in names
        assert "github_token" in names
        assert "ssn" in names
        assert "credit_card" in names
        assert "email_bulk" in names
        assert "phone_bulk" in names

    def test_shipped_config_compiles_all_patterns(self):
        """All patterns in shipped config compile successfully with re2."""
        compiled = _compile_custom_patterns(self.shipped_patterns)
        assert len(compiled) == len(self.shipped_patterns)
