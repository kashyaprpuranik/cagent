"""
mitmproxy addon: scan outbound request bodies for leaked secrets and PII.

Detects API keys, private keys, tokens, SSNs, credit cards, and bulk
PII (email/phone harvesting) in request bodies before they leave the
data plane.  Works alongside the existing mitm_addon.py (which re-routes
traffic to Envoy).

Runtime config is read from dlp_config.json in the same directory:
  {
    "enabled": false,
    "mode": "log",            # log | block | redact
    "skip_domains": [...],    # domains to skip scanning
    "disabled_patterns": [],  # built-in pattern names to disable
  }

Modes:
  log    - emit a JSON warning to stdout (Vector picks up via Docker logs)
  block  - return 403 and log the violation
  redact - replace matched secrets with [REDACTED] and log
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re2
import time
from pathlib import Path

from mitmproxy import http

logger = logging.getLogger("dlp_addon")

MAX_BODY_SCAN_BYTES = 1_048_576  # 1 MB

# Lightweight re import only for the base64 blob finder (no user input, safe)
import re as _re
_BASE64_BLOB_RE = _re.compile(r"[A-Za-z0-9+/=]{32,}")

# ---------------------------------------------------------------------------
# Built-in patterns  (name, compiled regex)
#
# Uses google-re2 for guaranteed linear-time matching (no ReDoS).
# RE2 does not support lookaround — patterns are written without it.
# The aws_secret_key context check (keyword nearby) is handled in
# _scan_text as a post-match filter.
# ---------------------------------------------------------------------------
BUILTIN_PATTERNS: list[tuple[str, re2.Pattern]] = [
    # --- Secrets ---
    ("aws_access_key", re2.compile(r"AKIA[0-9A-Z]{16}")),
    # aws_secret_key: 40-char base64-ish blob; context check done post-match
    ("aws_secret_key", re2.compile(r"[A-Za-z0-9/+=]{40}")),
    ("github_token", re2.compile(
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"
    )),
    ("openai_api_key", re2.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("anthropic_api_key", re2.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("private_key", re2.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )),
    ("jwt", re2.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )),
    ("generic_api_key", re2.compile(
        r"""(?i)(?:api_key|apikey|api-key|access_token|auth_token|secret_key)"""
        r"""[\s]*[=:]\s*['"]?[A-Za-z0-9_\-/.]{20,}['"]?"""
    )),
    ("connection_string", re2.compile(
        r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)"
        r"://[^\s'\"]{10,}"
    )),
    # --- PII ---
    ("ssn", re2.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re2.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")),
    # email_bulk and phone_bulk use threshold logic — see _BULK_PATTERNS below
]

# ---------------------------------------------------------------------------
# Bulk PII patterns (threshold-based, not single-match)
# ---------------------------------------------------------------------------
BULK_THRESHOLD = 5  # Flag only when >= this many individual matches appear

_BULK_PATTERNS: list[tuple[str, re2.Pattern]] = [
    ("email_bulk", re2.compile(r"[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")),
    ("phone_bulk", re2.compile(r"\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")),
]

# Patterns that need post-match context validation
_AWS_SECRET_CONTEXT_RE = re2.compile(r"(?i)(?:aws|secret|key)")

CONFIG_PATH = Path(__file__).parent / "dlp_config.json"


def _load_config(path: Path | str) -> dict:
    """Load DLP config from JSON, returning safe defaults on any error."""
    try:
        with open(path) as f:
            cfg = json.load(f)
        return {
            "enabled": bool(cfg.get("enabled", False)),
            "mode": cfg.get("mode", "log") if cfg.get("mode") in ("log", "block", "redact") else "log",
            "skip_domains": list(cfg.get("skip_domains", [])),
            "disabled_patterns": list(cfg.get("disabled_patterns", [])),
            "custom_patterns": list(cfg.get("custom_patterns", [])),
        }
    except (OSError, json.JSONDecodeError, TypeError):
        return {"enabled": False, "mode": "log", "skip_domains": [], "disabled_patterns": [], "custom_patterns": []}


def _try_base64_decode(text: str) -> str | None:
    """Attempt to base64-decode *text*.  Return decoded string or None."""
    # Quick pre-check: base64 should be mostly alphanumeric
    stripped = text.strip()
    if len(stripped) < 32:
        return None
    try:
        decoded = base64.b64decode(stripped, validate=True)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _scan_text(
    text: str,
    patterns: list[tuple[str, re2.Pattern]] | None = None,
    bulk_patterns: list[tuple[str, re2.Pattern]] | None = None,
) -> list[dict]:
    """Return list of {pattern_name, match} dicts for every secret found.

    *bulk_patterns* are threshold-based: only flagged when >= BULK_THRESHOLD
    individual matches appear in the text.
    """
    if patterns is None:
        patterns = BUILTIN_PATTERNS
    if bulk_patterns is None:
        bulk_patterns = _BULK_PATTERNS
    findings: list[dict] = []
    for name, pattern in patterns:
        for m in pattern.finditer(text):
            matched = m.group()
            # aws_secret_key: require context keyword nearby (replaces lookahead)
            if name == "aws_secret_key" and not _AWS_SECRET_CONTEXT_RE.search(text):
                continue
            findings.append({"pattern": name, "match": matched})
    # Bulk (threshold-based) patterns
    for name, pattern in bulk_patterns:
        matches = pattern.findall(text)
        if len(matches) >= BULK_THRESHOLD:
            findings.append({"pattern": name, "match": f"{len(matches)} instances"})
    return findings


def _redact_text(
    text: str,
    patterns: list[tuple[str, re2.Pattern]] | None = None,
    bulk_patterns: list[tuple[str, re2.Pattern]] | None = None,
) -> str:
    """Replace all secret matches with [REDACTED]."""
    if patterns is None:
        patterns = BUILTIN_PATTERNS
    if bulk_patterns is None:
        bulk_patterns = _BULK_PATTERNS
    result = text
    for _name, pattern in patterns:
        result = pattern.sub("[REDACTED]", result)
    # Bulk patterns: redact individual matches only when threshold is met
    for _name, pattern in bulk_patterns:
        matches = pattern.findall(result)
        if len(matches) >= BULK_THRESHOLD:
            result = pattern.sub("[REDACTED]", result)
    return result


def _emit_log(flow: http.HTTPFlow, findings: list[dict], mode: str) -> None:
    """Emit a structured JSON log line to stdout."""
    record = {
        "event": "dlp_violation",
        "timestamp": time.time(),
        "mode": mode,
        "method": flow.request.method,
        "host": flow.request.headers.get("Host", flow.request.pretty_host),
        "path": flow.request.path,
        "findings": [
            {"pattern": f["pattern"], "match_prefix": f["match"][:12] + "..."}
            for f in findings
        ],
    }
    # Structured JSON to stdout; Vector picks up via Docker json-file driver
    print(json.dumps(record), flush=True)


def _compile_custom_patterns(raw: list) -> list[tuple[str, re2.Pattern]]:
    """Compile custom pattern dicts into (name, regex) tuples.

    Invalid regexes are skipped with a warning.
    """
    compiled: list[tuple[str, re2.Pattern]] = []
    for entry in raw:
        name = entry.get("name", "")
        regex = entry.get("regex", "")
        if not name or not regex:
            continue
        try:
            compiled.append((name, re2.compile(regex)))
        except Exception as exc:
            logger.warning("Skipping invalid custom DLP pattern %r: %s", name, exc)
    return compiled


class DLPAddon:
    """mitmproxy addon that scans request bodies for secret and PII leakage."""

    def __init__(self, config_path: Path | str | None = None):
        path = Path(config_path) if config_path else CONFIG_PATH
        self.config = _load_config(path)
        disabled = set(self.config.get("disabled_patterns", []))
        self._patterns = [p for p in BUILTIN_PATTERNS if p[0] not in disabled]
        self._bulk_patterns = [p for p in _BULK_PATTERNS if p[0] not in disabled]
        self._custom_patterns = _compile_custom_patterns(self.config.get("custom_patterns", []))
        # Final combined list (for regular patterns only; bulk handled separately)
        self._all_patterns = self._patterns + self._custom_patterns

    def request(self, flow: http.HTTPFlow) -> None:
        if not self.config["enabled"]:
            return

        # Skip configured domains (e.g. LLM APIs with large prompt bodies)
        host = flow.request.headers.get("Host", flow.request.pretty_host)
        if host in self.config["skip_domains"]:
            return

        body = flow.request.get_text(strict=False)
        if not body:
            return

        # Truncate oversized bodies
        if len(body) > MAX_BODY_SCAN_BYTES:
            body = body[:MAX_BODY_SCAN_BYTES]

        # --- scan plain text ---
        findings = _scan_text(body, patterns=self._all_patterns, bulk_patterns=self._bulk_patterns)

        # --- scan base64-decoded content ---
        # Look for base64 blobs >= 32 chars (rough heuristic)
        for blob in _BASE64_BLOB_RE.findall(body):
            decoded = _try_base64_decode(blob)
            if decoded:
                b64_findings = _scan_text(decoded, patterns=self._all_patterns, bulk_patterns=self._bulk_patterns)
                for f in b64_findings:
                    f["pattern"] = f"base64:{f['pattern']}"
                findings.extend(b64_findings)

        if not findings:
            return

        mode = self.config["mode"]
        _emit_log(flow, findings, mode)

        if mode == "block":
            flow.response = http.Response.make(
                403,
                b"Blocked by DLP: request body contains sensitive data",
                {"Content-Type": "text/plain"},
            )
        elif mode == "redact":
            flow.request.set_text(_redact_text(body, patterns=self._all_patterns, bulk_patterns=self._bulk_patterns))


addons = [DLPAddon()]
