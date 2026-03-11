# Egress Body Inspection / DLP Plan

Inspect HTTP request and response bodies at the proxy layer to detect and block data exfiltration, secret leakage, and PII exposure through allowlisted domains.

## Motivation

Today cagent controls *where* traffic goes (domain allowlist, path filtering) but not *what's in it*. An agent can exfiltrate proprietary code, secrets, or PII through a POST to any allowlisted domain — paste source code into a GitHub issue, upload credentials to a Slack webhook, or send customer data to an LLM API.

This is the highest-risk gap in the current security model. The agent has access to the workspace (source code, configs) and can send arbitrary request bodies to any allowed endpoint. Domain allowlisting stops unauthorized destinations but does nothing about authorized destinations being misused.

## Threat Scenarios

| Scenario | Current Protection | With DLP |
|----------|-------------------|----------|
| Agent POSTs source code to GitHub issue | Allowed (github.com is allowlisted) | Blocked: detects code patterns |
| Agent sends .env contents to LLM API | Allowed (api.openai.com is allowlisted) | Blocked: detects secret patterns |
| Agent uploads SSH key to paste service | Blocked (paste service not allowlisted) | N/A (already blocked) |
| Agent embeds API key in a commit message | Allowed (github.com is allowlisted) | Blocked: detects API key patterns |
| Agent leaks PII in API request body | Allowed (if domain is allowlisted) | Blocked: detects PII patterns |
| Agent base64-encodes secrets before sending | Allowed | Detected: decode + re-scan |

## Architecture

```
    Cell
     │
     │ HTTPS request
     ▼
    mitmproxy (TLS termination)
     │
     │ plaintext HTTP (request body visible)
     ▼
    Envoy
     │
     │ ext_authz check
     ▼
    DLP Scanner (warden or sidecar)
     │
     ├── ALLOW (clean) ──► Envoy forwards to upstream
     ├── BLOCK (violation) ──► Envoy returns 403
     └── REDACT (partial) ──► Envoy forwards with body modified
```

The key insight: mitmproxy already decrypts HTTPS traffic. The plaintext request body flows through Envoy, which can call an ext_authz service for inspection. We already have this ext_authz flow for credential injection — DLP extends it to body scanning.

## Inspection Point

Two options for where scanning happens:

### Option A: mitmproxy addon (recommended)

Add a mitmproxy addon script that inspects request bodies before forwarding to Envoy. mitmproxy already sees the decrypted request; an addon can modify or block it inline.

```
Cell ──HTTPS──► mitmproxy ──[DLP addon scans body]──► Envoy ──► upstream
                                    │
                                    ├── clean: forward
                                    ├── violation: return 403
                                    └── redact: modify body, forward
```

Pros:
- mitmproxy already has the plaintext body — no extra hop
- Python addon — same language as warden, easy to maintain
- Can modify response bodies too (block inbound sensitive data)
- Handles both request and response in one place

Cons:
- Adds latency to every HTTPS request (scan time)
- mitmproxy addon runs in-process (crash = proxy crash)

### Option B: Envoy ext_authz extension

Extend the existing ext_authz call to warden to include body inspection. Envoy can forward request body bytes to the ext_authz service.

Pros:
- Reuses existing ext_authz infrastructure
- Warden already handles credential injection in ext_authz
- Covers both HTTP and HTTPS paths

Cons:
- Envoy ext_authz body forwarding has size limits (configurable but awkward for large bodies)
- Adds latency to ext_authz call (currently fast: header-only check)
- HTTP path (non-MITM) also gets scanned — may be unnecessary overhead

**Recommendation**: Option A (mitmproxy addon) for HTTPS, with Option B as a future extension for HTTP if needed. Most agent traffic is HTTPS; HTTP traffic through Envoy is primarily internal service aliases.

## Detection Patterns

### Secret detection

Regex-based patterns for common secret formats:

```python
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
    "github_token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "openai_api_key": r"sk-[A-Za-z0-9]{48}",
    "anthropic_api_key": r"sk-ant-[A-Za-z0-9-]{90,}",
    "generic_api_key": r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "connection_string": r"(?i)(postgres|mysql|mongodb|redis)://[^\s]{10,}",
}
```

### PII detection

```python
PII_PATTERNS = {
    "email_bulk": r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+.*){5,}",  # 5+ emails = bulk
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "phone_bulk": r"(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}.*){5,}",  # 5+ phones = bulk
}
```

### Code exfiltration heuristics

Not regex — structural analysis:

```python
def looks_like_code_dump(body: str) -> bool:
    """Heuristic: does this request body contain a large code block?"""
    lines = body.splitlines()
    if len(lines) < 20:
        return False

    code_indicators = 0
    for line in lines:
        stripped = line.strip()
        if any(stripped.startswith(kw) for kw in [
            "import ", "from ", "def ", "class ", "function ",
            "const ", "let ", "var ", "export ", "package ",
            "#include", "using ", "public ", "private ",
        ]):
            code_indicators += 1

    # >30% of lines look like code = suspicious
    return code_indicators / len(lines) > 0.3
```

### Encoding bypass detection

Agents may try to base64-encode secrets before sending:

```python
import base64

def scan_with_decode(body: str, patterns: dict) -> list:
    """Scan body and base64-decoded body for secret patterns."""
    violations = scan_body(body, patterns)

    # Try base64 decode on suspicious-looking strings
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for match in b64_pattern.finditer(body):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            violations.extend(scan_body(decoded, patterns))
        except Exception:
            pass

    return violations
```

## mitmproxy Addon

```python
# configs/mitm/dlp_addon.py

import re
import json
import logging
from mitmproxy import http

logger = logging.getLogger("dlp")

# Load patterns from config (mounted volume)
with open("/etc/mitmproxy/dlp_patterns.json") as f:
    DLP_CONFIG = json.load(f)

ENABLED = DLP_CONFIG.get("enabled", False)
MODE = DLP_CONFIG.get("mode", "log")  # "log", "block", "redact"
SECRET_PATTERNS = {k: re.compile(v) for k, v in DLP_CONFIG.get("secret_patterns", {}).items()}
MAX_BODY_SCAN = DLP_CONFIG.get("max_body_bytes", 1_000_000)  # 1MB cap


def scan_body(body: str) -> list:
    """Scan text for secret/PII patterns. Returns list of violations."""
    violations = []
    for name, pattern in SECRET_PATTERNS.items():
        matches = pattern.findall(body[:MAX_BODY_SCAN])
        if matches:
            violations.append({
                "pattern": name,
                "count": len(matches),
                # Don't log the actual secret — just the pattern name and count
            })
    return violations


class DLPAddon:
    def request(self, flow: http.HTTPFlow):
        if not ENABLED:
            return

        body = flow.request.get_text(strict=False)
        if not body or len(body) < 20:
            return

        violations = scan_body(body)
        if not violations:
            return

        # Log violation (always, regardless of mode)
        logger.warning(
            "DLP violation: %s %s -> %s violations=%s",
            flow.request.method,
            flow.request.host,
            flow.request.path,
            json.dumps(violations),
        )

        if MODE == "block":
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": "blocked_by_dlp",
                    "message": "Request blocked: contains sensitive data",
                    "violations": [v["pattern"] for v in violations],
                }),
                {"Content-Type": "application/json"},
            )

        elif MODE == "redact":
            text = flow.request.get_text()
            for name, pattern in SECRET_PATTERNS.items():
                text = pattern.sub(f"[REDACTED:{name}]", text)
            flow.request.set_text(text)


addons = [DLPAddon()]
```

## Configuration

DLP policy configured in `cagent.yaml`:

```yaml
# configs/cagent.yaml
dlp:
  enabled: true
  mode: log          # log | block | redact
  max_body_bytes: 1000000

  # Per-domain overrides
  skip_domains:
    - "api.openai.com"   # LLM APIs send large text bodies by design
    - "api.anthropic.com"

  # What to scan for
  secret_patterns:
    aws_access_key: "AKIA[0-9A-Z]{16}"
    github_token: "gh[ps]_[A-Za-z0-9_]{36,}"
    openai_api_key: "sk-[A-Za-z0-9]{48}"
    private_key: "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
    generic_api_key: "(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{20,}"

  pii_patterns:
    ssn: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    credit_card: "\\b(?:\\d{4}[- ]?){3}\\d{4}\\b"

  # Code exfiltration detection
  code_detection:
    enabled: true
    min_lines: 20          # minimum lines to trigger heuristic
    code_ratio_threshold: 0.3  # >30% code-like lines = flagged

  # Encoding bypass
  decode_base64: true
```

### Per-domain skip list

LLM APIs (OpenAI, Anthropic) inherently receive large text bodies — prompts containing code snippets, documentation, etc. These are expected and should not trigger DLP. The `skip_domains` list exempts them from body scanning while still applying domain allowlist, rate limiting, and credential injection.

For domains that need partial scanning (e.g., scan GitHub API for secrets but not for code patterns), per-domain pattern overrides:

```yaml
dlp:
  domain_overrides:
    "api.github.com":
      mode: block
      patterns: [secret_patterns]     # scan for secrets only, not code
    "*.slack.com":
      mode: block
      patterns: [secret_patterns, pii_patterns]  # full scan
```

## Alert Pipeline

```
mitmproxy DLP addon (violation detected)
    │
    │ logs to stdout (JSON)
    ▼
Vector (existing Docker log source)
    │
    │ transform: enrich with tenant_id, cell_id, severity
    ▼
    ├──► OpenObserve (local analytics)
    └──► CP API (connected mode audit trail)
```

### Alert format

```json
{
  "event_type": "dlp_violation",
  "timestamp": "2026-03-10T12:00:00Z",
  "severity": "critical",
  "action": "blocked",
  "request": {
    "method": "POST",
    "host": "api.github.com",
    "path": "/repos/org/repo/issues"
  },
  "violations": [
    {"pattern": "github_token", "count": 1},
    {"pattern": "private_key", "count": 1}
  ]
}
```

## What Changes

### mitmproxy

- New addon: `configs/mitm/dlp_addon.py`
- DLP config: `configs/mitm/dlp_patterns.json` (generated by warden from cagent.yaml)
- mitmproxy command updated to load DLP addon alongside existing `mitm_addon.py`

### docker-compose.yml

mitmproxy command adds the DLP addon:

```yaml
mitm-proxy:
  command: >
    mitmdump
    --mode regular
    --listen-port 8080
    --set confdir=/etc/mitmproxy
    --set stream_large_bodies=1m
    --set upstream_cert=false
    --set connection_strategy=lazy
    -s /etc/mitmproxy/mitm_addon.py
    -s /etc/mitmproxy/dlp_addon.py
```

### Warden

- Config generator: reads `dlp:` section from cagent.yaml, writes `dlp_patterns.json`
- New router: `/api/dlp/violations` — query recent violations from OpenObserve
- Admin UI: DLP violations panel

### cagent.yaml

- New `dlp:` section with patterns, mode, skip list

## Performance Considerations

| Concern | Mitigation |
|---------|------------|
| Scan latency per request | Cap at 1MB body scan; regex is fast (~1ms for typical patterns on 100KB body) |
| Large file uploads | `stream_large_bodies=1m` already set in mitmproxy — bodies >1MB are streamed, not buffered; DLP scans first 1MB only |
| LLM API prompts (large text) | skip_domains exempts LLM APIs from scanning |
| Regex backtracking on adversarial input | Use atomic groups / possessive quantifiers; set per-regex timeout |
| mitmproxy addon crash | mitmproxy restarts via docker `restart: unless-stopped`; DLP addon failures shouldn't block proxy (try/except around scan) |

## What Gets Added

- `configs/mitm/dlp_addon.py` — mitmproxy DLP addon
- `configs/mitm/dlp_patterns.json` — generated pattern config
- `cagent.yaml` `dlp:` section — DLP configuration
- `services/warden/routers/dlp.py` — violation query endpoint
- Vector transform for DLP events
- Admin UI DLP violations panel

## What Stays the Same

- Domain allowlist (CoreDNS + Envoy) — unchanged
- Credential injection (ext_authz) — unchanged
- Rate limiting (Envoy local_ratelimit) — unchanged
- mitmproxy TLS termination — unchanged (addon runs alongside)

## Risks

| Risk | Mitigation |
|------|------------|
| False positives on legitimate code in LLM prompts | skip_domains for LLM APIs; per-domain pattern overrides |
| Agent encodes data to bypass detection | base64 decode + re-scan; flag high-entropy blobs |
| Performance degradation on high-throughput cells | 1MB scan cap; fast regex; skip_domains for chatty APIs |
| Pattern maintenance burden | Start with well-known secret formats (AWS, GitHub, OpenAI); community patterns exist (truffleHog, detect-secrets) |
| DLP addon crash takes down proxy | try/except around all scan logic; mitmproxy auto-restarts; addon failure = allow (fail-open with alert) |
| Agent uses image/binary encoding to hide data | Phase 1 is text-only; binary/image steganography is out of scope (extremely low probability for LLM agents) |

## Migration Phases

### Phase 1: Log-only secret detection (3-4 days)

- Write mitmproxy DLP addon with secret pattern scanning
- Mode: `log` (scan and log violations, don't block)
- Warden generates `dlp_patterns.json` from cagent.yaml
- Vector picks up DLP logs, ships to OpenObserve
- Test: send a request containing a fake API key from cell, verify violation logged

### Phase 2: Blocking mode + skip list (3-4 days)

- Enable `block` mode for secret patterns
- Implement skip_domains and per-domain overrides
- Add base64 decode + re-scan
- Test: blocked request returns 403; LLM API requests pass through

### Phase 3: PII detection + per-pattern control (done)

- ~~Add PII patterns (SSN, credit card)~~ ✅
- ~~Bulk PII detection (email_bulk, phone_bulk with threshold >= 5)~~ ✅
- ~~Per-pattern enable/disable via `disabled_patterns` config~~ ✅
- ~~CP sync support for `disabled_patterns`~~ ✅
- Code exfiltration heuristic (structural analysis) — deferred to separate phase

### Phase 4: Dashboard + CP integration (3-4 days)

- Warden `/api/dlp/violations` endpoint (queries OpenObserve)
- Admin UI violations panel (violation timeline, top patterns, top destinations)
- CP audit trail integration (connected mode)
- Test: violation visible in admin UI within 10s

## Effort Estimate

- Phase 1: 3-4 days
- Phase 2: 3-4 days
- Phase 3: 3-4 days
- Phase 4: 3-4 days
- Total: ~2-3 weeks
