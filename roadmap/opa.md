# OPA Adoption Plan

Replace warden's custom ext_authz + config generation with Open Policy Agent (OPA).

## Motivation

Today warden does three jobs: CP sync, Envoy config generation, and request-path authz (ext_authz + credential injection). This couples sync timing to config reloads, makes policy changes require Envoy restarts, and puts custom code in the critical request path.

OPA separates these concerns: warden syncs, OPA decides.

## Architecture

```
                   ext_authz (HTTP)
    Envoy ──────────────────────────────► OPA
                                           │
                                           │ evaluates Rego policies
                                           │ against data bundles
                                           │
    Warden ─── bundle push ───────────────►│
      │
      │ syncs from CP (unchanged)
      ▼
    Control Plane
```

### What changes

| Component | Before | After |
|-----------|--------|-------|
| ext_authz provider | Warden (FastAPI endpoint) | OPA (standalone server) |
| Policy format | Python code in ext_authz.py | Rego policies (declarative, testable) |
| Credential injection | Warden resolves per-request | OPA returns headers from data bundle |
| Domain allowlist | Envoy virtual hosts (generated) | Rego policy evaluating request host |
| Rate limits | Envoy local_ratelimit (generated) | Keep in Envoy (OPA sets headers, Envoy enforces) |
| Config reload | Warden regenerates configs → Envoy hot reload | OPA pulls bundles, Envoy config is static |
| config_generator.py | Core of the system | Removed |

### What stays the same

- Envoy remains the egress gateway (routing, TLS, rate limiting)
- CoreDNS remains the DNS filter
- Warden remains the CP sync daemon
- mitmproxy remains the TLS terminator
- Docker networking (cell-net, infra-net) unchanged

## OPA Deployment

- Runs as a sidecar container on infra-net (like warden)
- ~15-20MB binary, minimal CPU/memory
- Stateless — all state comes from bundles
- Standalone server mode (not WASM filter) for simplicity and debuggability
- Listens on infra-net for ext_authz requests from Envoy

## Data Flow

1. Warden syncs domain policies + credentials from CP (existing flow, unchanged)
2. Warden builds OPA data bundle: `{ domains: {...}, credentials: {...} }`
3. Warden pushes bundle to OPA via bundle API (local HTTP, no network exposure)
4. Envoy sends ext_authz check to OPA for each request
5. OPA evaluates Rego policy against request + data bundle
6. OPA returns allow/deny + credential headers to inject

## Rego Policy Surface

```rego
package cagent.authz

import rego.v1

# Allow if domain is in the allowlist
default allow := false

allow if {
    domain := input.attributes.request.http.host
    data.domains[domain]
}

# Inject credentials if configured for this domain
headers["x-injected-authorization"] := credential if {
    domain := input.attributes.request.http.host
    credential := data.credentials[domain]
}
```

The actual policy will also handle:
- Path filtering (per-domain route rules)
- Wildcard domain matching
- Internal services passthrough
- Logging/audit decisions

## Bundle Format

```json
{
  "domains": {
    "api.github.com": {
      "allowed": true,
      "paths": ["/repos/*", "/user"],
      "rate_limit": 100
    },
    "*.googleapis.com": {
      "allowed": true
    }
  },
  "credentials": {
    "api.github.com": "Bearer ghp_xxx",
    "api.openai.com": "Bearer sk-xxx"
  },
  "internal_services": {
    "devbox.local": true
  }
}
```

## Migration Phases

### Phase 1: OPA sidecar + static policy (1 week)

- Add OPA container to docker-compose.yml (infra-net, static IP)
- Write basic Rego policy for domain allowlist (no credentials yet)
- Point Envoy ext_authz at OPA instead of warden
- Warden builds domain-only bundles from cagent.yaml
- Keep warden ext_authz endpoint as fallback (feature flag)
- Test: E2E tests pass with OPA in the path

### Phase 2: Credential injection via OPA (3-4 days)

- Add credentials to OPA data bundle
- Rego policy returns credential headers
- Remove warden ext_authz endpoint
- Test: credential injection works end-to-end

### Phase 3: Remove config_generator.py (3-4 days)

- Envoy config becomes static (no more generated virtual hosts)
- All domain routing decisions move to OPA
- Rate limit hints from OPA → Envoy local_ratelimit (or keep Envoy rate limits with static config)
- Remove config_generator.py
- Remove Envoy config reload logic from warden
- Test: full E2E with static Envoy + OPA

### Phase 4: Connected mode (2-3 days)

- Warden CP sync → OPA bundle pipeline for connected mode
- Remove domain policy proxy endpoint from warden (OPA handles it)
- Test: managed DP with CP-synced policies through OPA

## What Gets Removed

- `services/warden/routers/ext_authz.py`
- `services/warden/config_generator.py`
- `services/warden/routers/domain_policy.py` (after Phase 4)
- Generated Envoy config files (`configs/envoy/` becomes static)
- Generated CoreDNS Corefile logic (CoreDNS stays, but config could also come from OPA bundle)
- Envoy reload signaling in warden main loop

## What Gets Added

- `configs/opa/` directory (Rego policies, static config)
- OPA service in docker-compose.yml
- Bundle builder module in warden (`services/warden/opa_bundle.py`)
- Rego unit tests (`configs/opa/*_test.rego`)

## Risks

| Risk | Mitigation |
|------|------------|
| Rego learning curve | Policy surface is small (~100 lines); OPA Playground for iteration |
| Credential exposure in bundles | Bundles are local-only (infra-net), same trust boundary as warden today |
| OPA container failure | Envoy ext_authz `failure_mode_allow: false` → fail closed; health checks restart OPA |
| Rate limiting gap | Keep Envoy local_ratelimit with static config; OPA only does allow/deny + headers |

## Decision

Net infra debt reduction. Removes ~500 lines of custom Python (ext_authz, config_generator, domain_policy) and the fragile config-reload pipeline. Replaces with ~100 lines of Rego + a bundle builder. OPA is CNCF graduated, battle-tested, and purpose-built for this exact use case.

Total effort: ~2-3 weeks across all phases.
