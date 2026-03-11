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
    "custom_patterns": [...]  # pattern dicts: {name, regex, threshold?}
  }

All detection patterns (secrets and PII) are defined in custom_patterns.
In standalone mode, the shipped dlp_config.json contains sensible defaults.
In connected mode, the control plane pushes patterns via the DLP policy API.

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

CONFIG_PATH = Path(__file__).parent / "dlp_config.json"

# Compiled pattern tuple: (name, compiled_regex, threshold_or_None)
CompiledPattern = tuple[str, object, int | None]


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


def _compile_custom_patterns(raw: list) -> list[CompiledPattern]:
    """Compile pattern dicts into (name, regex, threshold) tuples.

    Each entry is a dict with 'name', 'regex', and optional 'threshold'.
    When threshold is set, the pattern uses count-based detection (e.g.
    flag only when >= threshold individual matches appear).

    Invalid regexes are skipped with a warning.
    """
    compiled: list[CompiledPattern] = []
    for entry in raw:
        name = entry.get("name", "")
        regex = entry.get("regex", "")
        if not name or not regex:
            continue
        threshold = entry.get("threshold")
        if threshold is not None:
            try:
                threshold = int(threshold)
            except (ValueError, TypeError):
                threshold = None
        try:
            compiled.append((name, re2.compile(regex), threshold))
        except Exception as exc:
            logger.warning("Skipping invalid DLP pattern %r: %s", name, exc)
    return compiled


def _scan_text(
    text: str,
    patterns: list[CompiledPattern] | None = None,
) -> list[dict]:
    """Return list of {pattern_name, match} dicts for every secret found.

    Patterns with a threshold are count-based: only flagged when the number
    of individual matches meets or exceeds the threshold.
    """
    if patterns is None:
        patterns = []
    findings: list[dict] = []
    for name, pattern, threshold in patterns:
        if threshold is not None:
            matches = pattern.findall(text)
            if len(matches) >= threshold:
                findings.append({"pattern": name, "match": f"{len(matches)} instances"})
        else:
            for m in pattern.finditer(text):
                findings.append({"pattern": name, "match": m.group()})
    return findings


def _redact_text(
    text: str,
    patterns: list[CompiledPattern] | None = None,
) -> str:
    """Replace all secret matches with [REDACTED]."""
    if patterns is None:
        patterns = []
    result = text
    for _name, pattern, threshold in patterns:
        if threshold is not None:
            matches = pattern.findall(result)
            if len(matches) >= threshold:
                result = pattern.sub("[REDACTED]", result)
        else:
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


class DLPAddon:
    """mitmproxy addon that scans request bodies for secret and PII leakage."""

    def __init__(self, config_path: Path | str | None = None):
        path = Path(config_path) if config_path else CONFIG_PATH
        self.config = _load_config(path)
        self._patterns = _compile_custom_patterns(self.config.get("custom_patterns", []))

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
        findings = _scan_text(body, patterns=self._patterns)

        # --- scan base64-decoded content ---
        # Look for base64 blobs >= 32 chars (rough heuristic)
        for blob in _BASE64_BLOB_RE.findall(body):
            decoded = _try_base64_decode(blob)
            if decoded:
                b64_findings = _scan_text(decoded, patterns=self._patterns)
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
            flow.request.set_text(_redact_text(body, patterns=self._patterns))


addons = [DLPAddon()]
