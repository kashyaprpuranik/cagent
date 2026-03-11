"""
mitmproxy addon: scan outbound request bodies for leaked secrets.

Detects API keys, private keys, tokens, and other sensitive patterns in
request bodies before they leave the data plane.  Works alongside the
existing mitm_addon.py (which re-routes traffic to Envoy).

Runtime config is read from dlp_config.json in the same directory:
  {
    "enabled": false,
    "mode": "log",            # log | block | redact
    "skip_domains": [...]     # domains to skip scanning
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
import re
import time
from pathlib import Path

from mitmproxy import http

logger = logging.getLogger("dlp_addon")

MAX_BODY_SCAN_BYTES = 1_048_576  # 1 MB

# ---------------------------------------------------------------------------
# Secret patterns  (name, compiled regex)
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    ("aws_secret_key", re.compile(
        r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
        r"(?=.*(?:aws|secret|key))",
        re.IGNORECASE,
    )),
    ("github_token", re.compile(
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"
    )),
    ("openai_api_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )),
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )),
    ("generic_api_key", re.compile(
        r"""(?:api_key|apikey|api-key|access_token|auth_token|secret_key)"""
        r"""[\s]*[=:]\s*['"]?[A-Za-z0-9_\-/.]{20,}['"]?""",
        re.IGNORECASE,
    )),
    ("connection_string", re.compile(
        r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)"
        r"://[^\s'\"]{10,}"
    )),
]

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
            "custom_patterns": list(cfg.get("custom_patterns", [])),
        }
    except (OSError, json.JSONDecodeError, TypeError):
        return {"enabled": False, "mode": "log", "skip_domains": [], "custom_patterns": []}


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
    patterns: list[tuple[str, re.Pattern[str]]] | None = None,
) -> list[dict]:
    """Return list of {pattern_name, match} dicts for every secret found."""
    if patterns is None:
        patterns = SECRET_PATTERNS
    findings: list[dict] = []
    for name, pattern in patterns:
        for m in pattern.finditer(text):
            findings.append({"pattern": name, "match": m.group()})
    return findings


def _redact_text(
    text: str,
    patterns: list[tuple[str, re.Pattern[str]]] | None = None,
) -> str:
    """Replace all secret matches with [REDACTED]."""
    if patterns is None:
        patterns = SECRET_PATTERNS
    result = text
    for _name, pattern in patterns:
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


def _compile_custom_patterns(raw: list) -> list[tuple[str, re.Pattern[str]]]:
    """Compile custom pattern dicts into (name, regex) tuples.

    Invalid regexes are skipped with a warning.
    """
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for entry in raw:
        name = entry.get("name", "")
        regex = entry.get("regex", "")
        if not name or not regex:
            continue
        try:
            compiled.append((name, re.compile(regex)))
        except re.error as exc:
            logger.warning("Skipping invalid custom DLP pattern %r: %s", name, exc)
    return compiled


class DLPAddon:
    """mitmproxy addon that scans request bodies for secret leakage."""

    def __init__(self, config_path: Path | str | None = None):
        path = Path(config_path) if config_path else CONFIG_PATH
        self.config = _load_config(path)
        self._custom_patterns = _compile_custom_patterns(self.config.get("custom_patterns", []))

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

        all_patterns = SECRET_PATTERNS + self._custom_patterns

        # --- scan plain text ---
        findings = _scan_text(body, patterns=all_patterns)

        # --- scan base64-decoded content ---
        # Look for base64 blobs >= 32 chars (rough heuristic)
        for blob in re.findall(r"[A-Za-z0-9+/=]{32,}", body):
            decoded = _try_base64_decode(blob)
            if decoded:
                b64_findings = _scan_text(decoded, patterns=all_patterns)
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
            flow.request.set_text(_redact_text(body, patterns=all_patterns))


addons = [DLPAddon()]
