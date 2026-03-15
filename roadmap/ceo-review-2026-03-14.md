# CEO Plan Review — Data Plane (2026-03-14)

Full architecture review of Cagent (DP + CP) in SCOPE EXPANSION mode. This doc captures DP-specific findings, build-now items, and vision items.

## Build Now (P1)

### 1. Alert + version rollback on config sync failure

**Status**: Not started
**Effort**: S
**Priority**: P1

**Problem**: If `config_generator` throws during policy sync (malformed CP response, template error), the DP silently keeps stale config. No alert to CP, no user visibility. Violates "zero silent failures."

**Fix**: On config generation failure:
1. Log error with full context (what was being synced, what failed, stack trace)
2. Send alert to CP via `POST /api/v1/cell/alerts` with `event_type=config_sync_failure`
3. Keep old config running (already happens)
4. Do NOT update local `policy_version` — this ensures the next heartbeat re-triggers a sync attempt

**Files**:
- `services/warden/config_sync.py` — wrap config generation in try/except, send alert on failure
- `services/warden/heartbeat_loop.py` — ensure policy_version not advanced on sync failure

**Error flow**:
```
CP returns new policy_version in heartbeat
    │
    ▼
Warden calls sync_config()
    │
    ├── SUCCESS: generate configs, apply, update local policy_version
    │
    └── FAILURE: log error, send alert to CP, keep old config
                 do NOT update local policy_version
                 next heartbeat will retry (version mismatch persists)
```

### 2. DNSSEC validation in CoreDNS

**Status**: Not started
**Effort**: S
**Priority**: P2

**Problem**: CoreDNS has no DNSSEC validation. A compromised infra-net service could spoof DNS responses, redirecting cell traffic to malicious hosts. Defense-in-depth gap.

**Fix**: Enable DNSSEC validation in CoreDNS `forward` plugin. CoreDNS supports this natively — just needs config change.

**Files**:
- `configs/coredns/Corefile` — add DNSSEC validation to forward block
- `services/warden/config_generator.py` — ensure generated Corefiles include DNSSEC
- `tests/` — add test verifying DNSSEC is enabled in generated Corefile

### 3. API key for warden admin endpoints

**Status**: Not started
**Effort**: S
**Priority**: P2

**Problem**: Warden's local admin API (port 8080) has no authentication. In connected mode, any container on infra-net can hit mutation endpoints (`PUT /api/config`, `POST /api/containers/{id}/restart`). The ext_authz and domain-policy endpoints (called by Envoy) must stay unauthenticated.

**Fix**: Generate a random API key at warden boot. Require it via `Authorization: Bearer <key>` for mutation endpoints. Read-only and Envoy-facing endpoints stay open.

**Details**:
- Generate key: `secrets.token_urlsafe(32)` on startup
- Print key to stdout on boot (so admin can copy it)
- In connected mode, pass key to CP during online ping so CP can use it for mTLS commands
- Endpoints requiring auth: `PUT /api/config`, `POST /api/containers/*`, `POST /api/commands/*`
- Endpoints staying open: `GET /api/health`, `POST /api/ext-authz/*`, `GET /api/domain-policies/*`, `GET /api/metrics`

**Files**:
- `services/warden/main.py` — generate key, add middleware
- `services/warden/routers/config.py` — require auth on PUT
- `services/warden/routers/containers.py` — require auth on mutations

### 4. Policy suggestion engine (delight)

**Status**: Not started
**Effort**: S
**Priority**: P2

**Problem**: When a cell gets a 403 for a domain not in the allowlist, the admin has no visibility into what the agent was trying to reach. They have to dig through Envoy access logs manually.

**Fix**: Parse Envoy access logs for 403 responses, extract the target domain, and surface them in the warden admin UI as "suggested domains" with a one-click "Allow" button.

**Details**:
- New warden endpoint: `GET /api/suggestions` — returns list of recently-blocked domains with request count and last-seen timestamp
- Parse from Envoy access logs (already collected by Vector) or from the catch-all route's 403 responses
- Deduplicate by domain, sort by frequency
- Admin UI: new "Suggestions" tab or banner on the domain policy page
- One-click "Allow" creates a new domain policy entry with sensible defaults

**Files**:
- `services/warden/routers/suggestions.py` — new router
- `services/warden/frontend/src/` — new UI component
- `services/warden/main.py` — register router

## Build Now (P2 — CP-dependent)

### 5. Cost estimation per cell (delight)

**Status**: Not started
**Effort**: M (DP portion: S)
**Priority**: P2

**DP portion**: Warden already has access to Envoy access logs with domain + request count. Add a new analytics widget that counts requests per domain per time window and returns it via the existing widget API. The cost mapping and display lives in CP (see CP roadmap).

**Files**:
- `services/warden/routers/analytics.py` — add requests-per-domain-per-hour aggregation

## Vision Items

### Agent activity timeline

**Effort**: M
**Priority**: P3

Visual timeline per cell showing all HTTP requests, color-coded by domain and status code, with expandable request/response details. Like a mini-Wireshark for agent network activity. Data already exists in OpenObserve — needs a new UI component and API endpoint to query and format it as a timeline.

### Behavioral baselines

**Effort**: L
**Priority**: P3
**Depends on**: Time-series data store (see CP roadmap)

Establish "normal" request patterns per agent (domains accessed, request frequency, payload sizes). Alert on anomalies (sudden new domains, large payloads, unusual hours). Requires a metrics backend — OpenObserve is a log store, not optimized for time-series aggregation at this scale.

### Semantic DLP

**Effort**: XL
**Priority**: P3

Current DLP uses regex patterns — misses novel encoding formats, images, binaries, and context-dependent secrets. Semantic DLP would use ML to understand content (code vs. credentials vs. PII) in context. Long-term vision item.

---

## Architecture Findings (reference)

### System architecture

```
┌───────────────────────────────────────────────────────────────┐
│ cell-net (10.200.1.0/24) — INTERNAL, no default gateway       │
│                                                                │
│  ┌─────────┐     ┌──────────┐     ┌──────────┐               │
│  │  Envoy  │ ←── │mitmproxy │ ←── │  CELL    │               │
│  │ :8443   │     │ :8080    │     │(sandbox) │               │
│  │ext_authz│     │ TLS term │     │          │               │
│  │→warden  │     │ DLP scan │     │  HTTP_PROXY=envoy        │
│  └────┬────┘     └──────────┘     │  HTTPS_PROXY=mitm        │
│       │                            │  DNS=coredns             │
│  ┌────┴────┐                      └──────────┘               │
│  │CoreDNS  │                                                  │
│  │ :53     │                                                  │
│  └─────────┘                                                  │
└───────────────────────────────────────────────────────────────┘
```

### Cell egress data flow (all paths)

```
CELL HTTP REQUEST
    │
    ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│ DNS Resolve  │ ──▶ │ Proxy Route  │ ──▶ │ ext_authz   │ ──▶ │ Upstream │
│ (CoreDNS)    │     │ (Envoy)      │     │ (Warden)    │     │ (internet)│
└──────┬───────┘     └──────┬───────┘     └──────┬──────┘     └──────────┘
       │                     │                     │
  [nil?] NXDOMAIN       [nil?] 403            [nil?] 403
  [empty?] NXDOMAIN     [empty?] 403          [empty?] no creds injected
  [error?] SERVFAIL     [error?] 503          [error?] 403 (timeout)
  [slow?] timeout       [slow?] 504           [slow?] 403 (timeout)
```

### Security findings (DP-specific)

| Finding | Severity | Status |
|---|---|---|
| DNSSEC missing in CoreDNS | High | Build now |
| Warden admin API unauthenticated | Medium | Build now |
| mitmproxy CA cert readable by cell | Medium | Mitigated (read-only FS) |
| DLP: no binary/image scanning | Medium | By design (P3 vision) |
| gVisor only in prod profile | Medium | Acceptable (dev mode is for dev) |

### Error paths (DP-specific)

| Codepath | Failure | Rescued? | User sees |
|---|---|---|---|
| ext_authz | Warden down | Y (403) | "403 Forbidden" |
| ext_authz | Credential not found | Y (no-op) | Request without creds |
| Heartbeat send | CP unreachable | Y (retry) | Cell offline after 3 misses |
| Config sync | Parse failure | NOW Y (alert) | Stale config + alert |
| Config sync | Config gen throws | NOW Y (alert) | Stale config + alert |
