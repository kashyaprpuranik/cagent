# Cagent Repository Analysis

Comprehensive analysis of the Cagent data plane codebase covering security, reliability, scalability, observability, logical correctness, and feature gaps.

---

## Table of Contents

1. [Security Issues](#1-security-issues)
2. [Reliability & Resilience Issues](#2-reliability--resilience-issues)
3. [Logical / Correctness Issues](#3-logical--correctness-issues)
4. [Scalability Concerns](#4-scalability-concerns)
5. [Observability Gaps](#5-observability-gaps)
6. [Code Quality & Maintainability](#6-code-quality--maintainability)
7. [Frontend Issues](#7-frontend-issues)
8. [Testing Gaps](#8-testing-gaps)
9. [Infrastructure & Configuration Issues](#9-infrastructure--configuration-issues)
10. [Feature Suggestions](#10-feature-suggestions)

---

## 1. Security Issues

### 1.1 CRITICAL: Agent Container Has Passwordless Sudo

**File:** `agent.Dockerfile:157`

```dockerfile
RUN echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/$USER_NAME
```

The agent user has unrestricted passwordless sudo. While the container is network-isolated, a compromised agent can escalate to root within the container, potentially exploiting kernel vulnerabilities or gVisor escapes. This undermines the defense-in-depth strategy.

**Recommendation:** Remove sudo entirely or restrict it to specific commands needed for the agent's operation (e.g., `apt-get install`). At minimum, disable `sudo` in the `standard` (production) profile.

### 1.2 CRITICAL: No Authentication on Warden API

**File:** `services/warden/main.py:1047-1053`

The warden API has no authentication. Any service on `infra-net` can:
- Modify `cagent.yaml` via `PUT /api/config`
- Restart/stop agent containers via `POST /api/containers/{name}`
- Access the WebSocket terminal via `/api/terminal/{name}`
- Start/stop SSH tunnels
- Read credentials (via config endpoints)

The CORS middleware only limits browser-based access from specific origins, but API calls from within the Docker network are unrestricted.

**Recommendation:** Add API key or mTLS authentication for the warden API. At minimum, separate internal-only endpoints (domain policy for Lua filter) from admin endpoints.

### 1.3 HIGH: Credential Leakage via Access Logs

**File:** `configs/envoy/filter.lua:362-364`

After credential injection, the injected credential header (e.g., `Authorization: Bearer sk-...`) flows through Envoy and is potentially captured in access logs. While the access log config doesn't explicitly log request headers, Vector's `parse_docker` transform (`configs/vector/vector.yaml:54`) captures the raw message which includes the JSON access log. If a debug-level log config is enabled, credentials could leak to log files, S3, or Elasticsearch.

**Recommendation:** Add a response filter that strips credential-related headers before logging. Alternatively, redact the credential value in the Lua filter after injection by setting a flag rather than the full header value in tracking headers.

### 1.4 HIGH: Docker Socket Mounted Read-Only but Still Powerful

**File:** `docker-compose.yml:405`

```yaml
- /var/run/docker.sock:/var/run/docker.sock:ro
```

The Docker socket is mounted into `warden` and `log-shipper`. Even read-only, the Docker socket provides broad access to inspect containers, read environment variables (which may contain secrets), and view logs. With the lack of API auth on warden, this becomes an amplified risk.

**Recommendation:** Consider using a Docker socket proxy (like [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)) that limits allowed API calls to only what warden needs.

### 1.5 HIGH: Config Update Endpoint Lacks Input Validation

**File:** `services/warden/routers/config.py:67-84`

The `PUT /api/config/raw` endpoint accepts arbitrary YAML content and writes it directly to `cagent.yaml`. While it validates YAML syntax, it does not validate the schema or content. An attacker could:
- Inject malicious domain entries
- Set `security.seccomp_profile: permissive` to disable sandboxing
- Add credential entries pointing to attacker-controlled env vars

**Recommendation:** Add schema validation for the config content. Validate domain entries, credential references, and security settings against expected schemas.

### 1.6 MEDIUM: Lua Filter JSON Parsing via Regex is Fragile

**File:** `configs/envoy/filter.lua:183-224`

The `parse_domain_policy_response` function uses regex-based JSON parsing:
```lua
local policy = {
    matched = string.match(body, '"matched"%s*:%s*true') ~= nil,
    ...
}
```

This is fragile and potentially exploitable. A crafted JSON response could include `"matched": true` in a string value, causing the parser to incorrectly match. Envoy's Lua runtime doesn't include a JSON parser by default, but this approach is error-prone.

**Recommendation:** Use a proper JSON parser (e.g., embed `cjson` or `dkjson` in the Envoy container) or restructure the protocol to use simpler, unambiguous response formats (e.g., header-based responses).

### 1.7 MEDIUM: Tunnel Client Secret Key Written to `/tmp`

**File:** `configs/frpc/entrypoint.sh:75-97`

The FRP configuration including `secretKey` and `auth.token` is written to `/tmp/frpc.toml` in plaintext. Any process in the tunnel-client container can read these credentials.

**Recommendation:** Write the config to a tmpfs mount or use environment variables directly. Set restrictive file permissions (600) on the config file.

### 1.8 MEDIUM: Envoy Image Uses `latest` Tag

**File:** `docker-compose.yml:271`

```yaml
image: envoyproxy/envoy:v1.28-latest
```

Using `v1.28-latest` means any patch update within v1.28 is automatically pulled. While better than a bare `latest`, this can introduce unexpected behavior changes. Similarly, `coredns/coredns:latest` and `snowdreamtech/frpc:latest` are unpinned.

**Recommendation:** Pin all images to specific versions (e.g., `envoyproxy/envoy:v1.28.2`, `coredns/coredns:1.11.1`).

### 1.9 MEDIUM: WebSocket Terminal Has No Rate Limiting or Session Limits

**File:** `services/warden/routers/terminal.py`

The WebSocket terminal endpoint has no:
- Rate limiting on connection attempts
- Maximum concurrent session limit
- Idle timeout (beyond the 30s socket timeout)
- Audit logging of terminal sessions

**Recommendation:** Add connection rate limiting, max concurrent sessions, and audit logging of terminal access.

### 1.10 LOW: Read-Only Bypass on DELETE Methods for PyPI/npm

**File:** `configs/envoy/envoy-enhanced.yaml:109-128` and `config_generator.py:214-225`

The `read_only` enforcement blocks `POST`, `PUT`, and `DELETE` but not `PATCH`. While PyPI and npm don't use `PATCH` for writes, this is an incomplete implementation of read-only enforcement.

**Recommendation:** Block all non-safe methods (`POST`, `PUT`, `DELETE`, `PATCH`) for read-only domains, or use a whitelist approach allowing only `GET`, `HEAD`, `OPTIONS`.

---

## 2. Reliability & Resilience Issues

### 2.1 HIGH: Config Regeneration Can Leave Envoy in Inconsistent State

**File:** `services/warden/main.py:610-622`

```python
if envoy_changed or lua_changed:
    if envoy_changed:
        config_generator.write_envoy_config(ENVOY_CONFIG_PATH)
    if lua_changed:
        config_generator.write_lua_filter(ENVOY_LUA_PATH)
    reload_envoy()
```

If the Envoy config write succeeds but the Lua filter write fails, Envoy restarts with a new config but old Lua filter, potentially causing a mismatch. Similarly, if the Envoy restart itself fails, the new config is on disk but Envoy is running with the old config.

**Recommendation:** Write configs atomically (write to temp file, then rename). Validate the new config before restarting Envoy (e.g., `envoy --mode validate`). Implement rollback on failure.

### 2.2 HIGH: Container Recreation Has No Rollback

**File:** `services/warden/main.py:154-299`

`recreate_container_with_seccomp()` stops and removes the old container before creating the new one. If the new container creation fails (e.g., image not found, network error), the agent is permanently destroyed with no recovery path.

**Recommendation:** Create the new container first, verify it starts successfully, then remove the old one. Alternatively, keep a snapshot of the old container's config for recovery.

### 2.3 HIGH: `docker_client` is a Module-Level Singleton Without Reconnection

**File:** `services/warden/constants.py:9`

```python
docker_client = docker.from_env()
```

The Docker client is created once at module import time. If the Docker daemon restarts or the socket becomes unavailable, all subsequent Docker operations will fail permanently until the warden is restarted.

**Recommendation:** Implement a lazy Docker client with automatic reconnection, or wrap Docker operations in a retry decorator that recreates the client on connection failure.

### 2.4 MEDIUM: `MANAGED_CONTAINERS` is Computed Once at Import Time

**File:** `services/warden/constants.py:114`

```python
MANAGED_CONTAINERS = get_managed_containers()
```

This is evaluated at import time and never refreshed. If containers are added/removed at runtime (e.g., scaling agents), the list becomes stale. The containers endpoint will miss newly created containers.

**Recommendation:** Make `get_managed_containers()` a function call at request time, or refresh it periodically.

### 2.5 MEDIUM: Main Loop Catches All Exceptions Silently

**File:** `services/warden/main.py:1020-1021`

```python
except Exception as e:
    logger.error(f"Error in main loop: {e}")
```

The main loop catches all exceptions and continues. While this prevents the loop from crashing, it means persistent errors (e.g., disk full, Docker socket gone) will be silently retried every `HEARTBEAT_INTERVAL` seconds, flooding logs without any escalation.

**Recommendation:** Implement exponential backoff on repeated failures. Add a circuit breaker that pauses the loop after N consecutive failures. Expose a health metric for the polling loop.

### 2.6 MEDIUM: No Graceful Shutdown for Background Thread

**File:** `services/warden/main.py:1034`

```python
loop_thread = threading.Thread(target=main_loop, daemon=True)
```

The main loop thread is a daemon thread, so it's killed abruptly on process exit. If the loop is in the middle of a container operation (e.g., recreating a container), this could leave the system in an inconsistent state.

**Recommendation:** Use a shutdown event (`threading.Event`) to signal the loop to stop gracefully. Handle SIGTERM to trigger the shutdown.

### 2.7 MEDIUM: Agent Entrypoint Hangs on `tail -f /dev/null`

**File:** `agent_entrypoint.sh:104`

```bash
exec tail -f /dev/null
```

If the SSH daemon crashes, the container remains running (due to `tail -f /dev/null`) but is inaccessible. The healthcheck (`kill -0 1`) only checks that PID 1 is alive, which will always be true since `tail` is PID 1 after `exec`.

**Recommendation:** Use a process supervisor (e.g., `tini`, `dumb-init`) or check SSH daemon health in the healthcheck. Consider `exec /usr/sbin/sshd -D` to make sshd PID 1.

### 2.8 LOW: DNS Cache TTL Mismatch

The CoreDNS cache TTL is set to 300s (from `cagent.yaml`), but the Lua filter domain policy cache is also 300s. If a domain is removed from the allowlist, it could remain resolvable in DNS for up to 300s and have valid policy cache for another 300s — a total of up to 10 minutes of stale access.

**Recommendation:** Make the Lua filter cache TTL shorter (e.g., 60s) or implement a cache invalidation push mechanism.

---

## 3. Logical / Correctness Issues

### 3.1 HIGH: Rate Limiting is Per-Worker, Not Per-Proxy

**File:** `configs/envoy/filter.lua:262-293`

The token bucket rate limiter uses Lua script-level variables (`token_buckets`). In Envoy, Lua scripts run per worker thread, so each worker has its own independent rate limit state. With the default 2 worker threads, actual throughput is 2x the configured limit.

**Recommendation:** Use Envoy's built-in rate limiting (via `envoy.filters.http.local_ratelimit` or an external rate limit service) instead of Lua-based rate limiting. Alternatively, divide the configured rate by the number of workers.

### 3.2 HIGH: Rate Limiter Uses `os.time()` Which Has 1-Second Granularity

**File:** `configs/envoy/filter.lua:265`

```lua
local now = os.time()
```

`os.time()` returns integer seconds. For a rate limit of 60 RPM (1 request/second), burst requests within the same second all see the same `elapsed` value of 0, meaning no token refill occurs. This makes the rate limiter overly aggressive for short bursts and under-protective for second-boundary bursts.

**Recommendation:** Use `os.clock()` or Envoy's built-in timing facilities for sub-second precision.

### 3.3 MEDIUM: Wildcard Domain Matching Inconsistency Between CoreDNS and Envoy

**File:** `services/warden/config_generator.py:116-120`

For wildcard domains like `*.github.com`, CoreDNS only gets the base domain `github.com` added. This means `sub.github.com` won't resolve via DNS but would be allowed by the Envoy Lua filter's wildcard matching logic. The DNS layer and proxy layer are inconsistent.

**Recommendation:** For wildcard entries, add both the base domain and a catch-all `template` block in CoreDNS that matches subdomains.

### 3.4 MEDIUM: `_stable_hash` Can Produce False Negatives

**File:** `services/warden/main.py:557-563`

```python
def _stable_hash(content: str) -> str:
    stable = "\n".join(
        line for line in content.splitlines()
        if "Generated:" not in line
    )
    return hashlib.md5(stable.encode()).hexdigest()
```

This strips any line containing "Generated:" anywhere, not just the header comment. If a domain entry or comment contains the string "Generated:", it would be silently stripped from the hash computation, potentially causing config changes to be missed.

**Recommendation:** Only strip the specific auto-generated header lines (e.g., lines starting with `# Generated:`).

### 3.5 MEDIUM: `config/reload` Endpoint Doesn't Regenerate Configs

**File:** `services/warden/routers/config.py:87-106`

The `/api/config/reload` endpoint restarts CoreDNS and Envoy but does not actually regenerate configs from `cagent.yaml`. If a user modifies the config via the API and then triggers a reload, the containers restart with potentially stale generated configs.

**Recommendation:** Call `regenerate_configs()` from `main.py` before restarting the containers, or make `reload_config` trigger a full regeneration cycle.

### 3.6 MEDIUM: E2E Echo Server Domain Leaked into Production Config

**File:** `configs/cagent.yaml:166-171`

```yaml
  - domain: echo-server
    alias: echo
    credential:
      header: Authorization
      format: "Bearer {value}"
      env: E2E_ECHO_CREDENTIAL
```

The E2E test echo-server domain with credential configuration is present in the production config file. While the env var likely won't be set in production, this pollutes the allowlist and generated configs.

**Recommendation:** Move the echo-server entry to a test-specific config overlay rather than the main config file.

### 3.7 LOW: `cagent.yaml` Has Structural Issue

**File:** `configs/cagent.yaml:165-166`

The echo-server entry appears after the email section comments but is still under the `domains` key. The indentation makes it unclear whether it's intended to be part of the domains list. If the YAML is re-parsed after programmatic modifications, this could break.

### 3.8 LOW: Containers Router Uses Stale `MANAGED_CONTAINERS`

As noted in 2.4, but this also means the `GET /api/containers` endpoint returns a fixed set of containers that doesn't reflect runtime changes.

---

## 4. Scalability Concerns

### 4.1 HIGH: `container.stats(stream=False)` Blocks Per Container

**Files:** `services/warden/main.py:427`, `services/warden/routers/containers.py:29`

`container.stats(stream=False)` is a blocking Docker API call that waits for a full stats cycle (~1-2 seconds per container). With multiple agent containers:
- The heartbeat loop with 20+ containers will take 20-40+ seconds per cycle
- The `GET /api/containers` endpoint serializes stats calls, taking O(N) seconds

**Recommendation:** Use async stats collection or cache stats with background refresh. For the API endpoint, consider returning cached stats instead of real-time ones.

### 4.2 MEDIUM: Single-Instance Architecture with No HA Support

The warden, dns-filter, and http-proxy are all single-instance with `container_name` set (preventing scaling). For production deployments with multiple agents, these become single points of failure.

**Recommendation:** Document (or implement) HA patterns:
- DNS: Run multiple CoreDNS replicas behind a virtual IP
- Proxy: Run multiple Envoy instances with shared config
- Warden: Support leader election or stateless API mode

### 4.3 MEDIUM: Domain Policy Cache Has No Size Limit

**File:** `configs/envoy/filter.lua:12`

```lua
local domain_policy_cache = {}
```

The Lua domain policy cache grows unboundedly. A malicious agent could request thousands of unique domains, each cached for 5 minutes, consuming Envoy worker memory.

**Recommendation:** Add an LRU eviction policy or a maximum cache size to the domain policy cache.

### 4.4 LOW: Log Parsing in Analytics Is O(N) Over All Logs

**File:** `services/warden/routers/analytics.py:21-32`

Every analytics API call reads the full Docker log output for the time window and parses it line by line in Python. For high-traffic deployments, this will be slow and memory-intensive.

**Recommendation:** Consider indexing logs or using a pre-aggregated metrics store. Alternatively, expose Envoy's built-in stats (`/stats`) rather than parsing access logs.

---

## 5. Observability Gaps

### 5.1 HIGH: No Structured Metrics Endpoint

The warden has no Prometheus/metrics endpoint. Key metrics that should be exposed:
- Heartbeat success/failure rate
- Config sync latency and status
- Container discovery count
- Rate limit hits per domain
- Domain policy cache hit/miss ratio
- API request latency

**Recommendation:** Add a `/metrics` endpoint using `prometheus_client` or `starlette-prometheus`.

### 5.2 HIGH: No Alerting on Security-Critical Events

There's no mechanism to alert on:
- Blocked domains hitting high thresholds (potential exfiltration attempts)
- DNS tunneling detections
- Rate limit violations
- Seccomp profile violations (gVisor audit logs with denied syscalls)
- Failed authentication attempts (in connected mode)

**Recommendation:** Add Vector transforms that detect anomalous patterns and either send alerts (webhook/email) or expose them as metrics for an external alerting system.

### 5.3 MEDIUM: No Request Tracing/Correlation

Requests flowing through agent -> DNS -> Envoy -> upstream have no correlation ID. When diagnosing issues, there's no way to trace a single request across all layers.

**Recommendation:** Generate a unique request ID in the Lua filter and propagate it through all log entries. Vector can then correlate logs across sources.

### 5.4 MEDIUM: gVisor Logs Only Collected When Auditing Profile Is Active

**File:** `docker-compose.yml:328-373`

The log-shipper (and gVisor log collection) only runs with `--profile auditing`. In the default `standard` profile with gVisor enabled, security-critical syscall audit logs are not collected.

**Recommendation:** Either make log-shipper a non-optional dependency of the `standard` profile, or collect gVisor logs through a simpler mechanism (e.g., file tailing from a shared volume).

### 5.5 LOW: No Health Dashboard for Standalone Mode

In standalone mode, there's no aggregated health view. The admin UI provides individual container status, but there's no single endpoint that reports overall system health (config freshness, all containers healthy, DNS working, proxy working).

**Recommendation:** Add a `/api/health/detailed` endpoint that checks all system components and returns an aggregate health status with specific failure reasons.

---

## 6. Code Quality & Maintainability

### 6.1 MEDIUM: Duplicated Container Stats Logic

Container stats collection is duplicated between:
- `services/warden/main.py:425-445` (`get_container_status`)
- `services/warden/routers/containers.py:28-44` (`get_container_info`)

Both implement the same CPU/memory calculation independently.

**Recommendation:** Extract container stats collection into a shared utility function in `constants.py` or a new `utils.py`.

### 6.2 MEDIUM: Duplicated Wildcard Domain Matching

Wildcard domain matching is implemented independently in three places:
- `configs/envoy/filter.lua:104-123` (Lua)
- `services/warden/routers/domain_policy.py:87-96` (Python)
- `services/warden/config_generator.py:116-120` (Python, for CoreDNS)

Each has slightly different semantics, leading to inconsistencies (see issue 3.3).

**Recommendation:** Centralize domain matching logic in a single Python function and use it consistently. The Lua implementation should mirror the authoritative Python logic.

### 6.3 MEDIUM: No Data Validation Models for API Responses

The API returns raw dicts without Pydantic response models. This means:
- No automatic API documentation for response schemas
- No validation that responses match expected shapes
- Frontend must guess response structures

**Recommendation:** Add Pydantic response models for all API endpoints.

### 6.4 LOW: `MD5` Used for Config Hashing

**File:** `services/warden/config_generator.py:36`, `main.py:563`

MD5 is used for config change detection. While this isn't a security context, using a deprecated hash algorithm is a code smell and may trigger security scanners.

**Recommendation:** Use `hashlib.sha256` instead.

### 6.5 LOW: Sync HTTP Calls (`requests`) in Async FastAPI Endpoints

**File:** `services/warden/routers/domain_policy.py:171`

The domain policy endpoint uses synchronous `requests.get()` inside an async endpoint. This blocks the event loop and can cause request queuing under load.

**Recommendation:** Use `httpx.AsyncClient` for HTTP calls within async endpoints.

---

## 7. Frontend Issues

### 7.1 MEDIUM: No Error Boundaries

If any React component throws during rendering, the entire app crashes. There are no error boundaries to catch and display errors gracefully.

**Recommendation:** Add React error boundaries around major page sections.

### 7.2 MEDIUM: No CSRF Protection

The frontend makes API calls to the warden without CSRF tokens. Combined with the permissive CORS policy (which allows credentials from localhost origins), this enables CSRF attacks if a user visits a malicious page while the admin UI is running.

**Recommendation:** Add CSRF token middleware to FastAPI, or switch to cookie-less auth (API key in header).

### 7.3 LOW: Frontend Dev Server Proxy Not Configured for WebSocket

If the Vite dev server proxies API calls to the backend, WebSocket connections (for the terminal) may not be properly proxied, causing development-time issues.

### 7.4 LOW: No Input Sanitization for Domain Names in Admin UI

Domain names entered in the admin UI are sent directly to the API without client-side validation. While the API should validate, defense in depth suggests client-side validation too.

---

## 8. Testing Gaps

### 8.1 HIGH: No Tests for Lua Filter Logic

The Lua filter is the most security-critical component (credential injection, rate limiting, DNS tunneling detection, path filtering) but has zero unit tests. All testing relies on E2E tests which are slow and don't cover edge cases.

**Recommendation:** Add Lua unit tests (using `busted` or similar) for:
- `detect_dns_tunneling` with boundary cases
- `match_domain_wildcard` with edge cases
- `parse_domain_policy_response` with malformed inputs
- Rate limiter token bucket math
- Path matching with edge cases

### 8.2 HIGH: No Tests for Container Recreation / Seccomp Update

The `recreate_container_with_seccomp` function is complex (299 lines of container management) with many failure modes but has no unit tests. Container recreation bugs could destroy running agents.

**Recommendation:** Add tests using mocked Docker client to cover:
- Successful recreation
- Failure during stop (old container still running)
- Failure during create (old container gone, new one fails)
- Network reconnection failures

### 8.3 MEDIUM: No Negative Security Tests

There are no tests verifying that security controls actually block attacks:
- DNS tunneling is blocked
- Non-allowlisted domains are rejected
- Rate limits are enforced
- Credential injection doesn't leak to logs
- `read_only` mode actually blocks mutating requests
- Seccomp profiles block expected syscalls

**Recommendation:** Add security-focused test suite covering bypass attempts.

### 8.4 MEDIUM: E2E Tests Require Full Docker Environment

E2E tests cannot run in CI environments without Docker-in-Docker or a pre-provisioned Docker host. This limits test coverage in automated pipelines.

**Recommendation:** Add a lightweight integration test tier using `testcontainers` that can run in standard CI. Mock the Docker socket for unit tests.

### 8.5 LOW: No Frontend Tests

The React frontend has no unit or integration tests. Only TypeScript compilation is checked.

**Recommendation:** Add Jest/Vitest tests for critical components, especially the config editor and container management UI.

---

## 9. Infrastructure & Configuration Issues

### 9.1 MEDIUM: No Config Schema Validation

`cagent.yaml` has no formal schema. Invalid configurations are only caught when they cause runtime errors. For example:
- A typo like `domains` -> `domians` would silently result in an empty allowlist
- An invalid `seccomp_profile` value could crash the seccomp update logic
- Missing `rate_limits` defaults could cause division errors

**Recommendation:** Add a JSON Schema or Pydantic model for `cagent.yaml` and validate on load. Fail loudly with clear error messages.

### 9.2 MEDIUM: No Backup Before Config Modification

**File:** `services/warden/routers/config.py:59-61`

Config updates via the API overwrite `cagent.yaml` directly with no backup. If a bad config is written, the only recovery is to manually restore from git.

**Recommendation:** Create a timestamped backup of the current config before writing changes. Keep the last N backups.

### 9.3 MEDIUM: No Health Checks for Envoy Upstream Connectivity

Envoy clusters use `LOGICAL_DNS` with no health checking enabled. If an upstream (e.g., `api.github.com`) becomes unavailable, Envoy will continue routing to it and return 5xx errors until the DNS TTL expires.

**Recommendation:** Add Envoy health checks for upstream clusters, or at minimum implement passive health checking (outlier detection).

### 9.4 LOW: Vector API Exposed on 0.0.0.0

**File:** `configs/vector/vector.yaml:9`

```yaml
api:
  enabled: true
  address: "0.0.0.0:8686"
```

The Vector API is bound to all interfaces. While it's only accessible from infra-net, this is unnecessarily broad.

**Recommendation:** Bind to `127.0.0.1` or the specific infra-net IP.

### 9.5 LOW: No TLS Between Internal Services

All internal communication (warden <-> Envoy, warden <-> control plane within Docker network) is unencrypted HTTP. While Docker networks provide some isolation, a compromised container on infra-net could sniff traffic.

**Recommendation:** Enable mTLS between internal services for defense in depth, especially for credential-bearing traffic.

---

## 10. Feature Suggestions

### 10.1 Egress Allowlist by IP Range

Currently only domain-based allowlisting is supported. Some use cases require allowing access by IP range (e.g., internal network CIDR blocks).

### 10.2 Request Body Inspection for DLP

Add optional data loss prevention (DLP) inspection of outgoing request bodies to prevent exfiltration of sensitive data (API keys, PII, source code) through allowed domains.

### 10.3 Per-Agent Domain Policies

Currently, all agents share the same domain allowlist. Multi-tenant deployments would benefit from per-agent or per-agent-group policies.

### 10.4 Config Drift Detection

Detect when generated configs (Corefile, Envoy config) are manually modified outside of the normal generation flow, and alert or auto-correct.

### 10.5 Credential Rotation Support

Add support for automatic credential rotation. Currently, credentials are static environment variables. Support for:
- Vault integration for dynamic secrets
- Automatic OAuth token refresh for API credentials
- Credential expiry alerts

### 10.6 Network Policy Visualization

Add a network topology visualization in the admin UI showing:
- Which domains agents are accessing
- Traffic flow between components
- Real-time blocked/allowed request ratios

### 10.7 Agent Workspace Snapshots

Add the ability to snapshot and restore agent workspaces, enabling:
- Pre-seeded development environments
- Quick workspace recovery after wipe
- Template-based agent provisioning

### 10.8 Egress Budget / Cost Tracking

Track egress data usage per domain and enforce data transfer budgets. Useful for controlling API costs (e.g., limiting total tokens sent to OpenAI).

### 10.9 WebSocket Proxy Support

The current Envoy configuration only handles HTTP CONNECT for HTTPS. WebSocket connections from the agent to allowed domains may not work correctly through the proxy.

### 10.10 Multi-Platform Agent Images

The Dockerfile only builds for `amd64`. Add multi-arch support (ARM64) for deployment on ARM-based cloud instances and Apple Silicon development machines.

### 10.11 Granular Audit Logging

Add structured audit logs for all administrative actions:
- Config changes (who, what, when)
- Container lifecycle events
- SSH tunnel creation/teardown
- Terminal session starts/ends

### 10.12 Envoy Hot Restart Instead of Full Restart

**File:** `services/warden/main.py:538-550`

Currently, config changes trigger a full Envoy container restart. Envoy supports hot restart which can apply config changes without dropping connections.

**Recommendation:** Use Envoy's admin API for config updates or implement hot restart for zero-downtime config changes.

---

## Priority Summary

| Priority | Count | Key Items |
|----------|-------|-----------|
| **CRITICAL** | 2 | Passwordless sudo in agent container, No API authentication |
| **HIGH** | 10 | Credential leakage, inconsistent config state, rate limit bypass, no Lua tests, no container recreation tests |
| **MEDIUM** | 18 | Stale container lists, sync HTTP in async endpoints, no metrics, no schema validation |
| **LOW** | 10 | MD5 usage, frontend gaps, Vector API binding, missing multi-arch |

---

*Analysis performed on 2026-02-17 against the current state of the `main` branch.*
