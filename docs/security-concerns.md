# Security Concerns

Known security concerns in the current codebase, organized by severity. Items already tracked in the [Roadmap](../README.md#roadmap) (mTLS, improved secret management, alert rules) are excluded.

---

## High

### 1. No TLS certificate validation on Envoy upstream connections

Envoy upstream clusters configure TLS with SNI but do not set `validation_context` or `trusted_ca`. Without certificate verification, a network-level attacker who can intercept DNS or routing can MITM upstream API calls (GitHub, PyPI, OpenAI, Anthropic, etc.) and capture injected credentials.

- `data_plane/configs/envoy/envoy-enhanced.yaml:347-351` (github_api cluster, same pattern for all clusters through line 451)

**Recommendation:** Add `validation_context` with system CA bundle to each upstream `UpstreamTlsContext`.

### 2. Unsalted SHA-256 for token hashing

Tokens are hashed with plain SHA-256 and no salt. If the token hash database is compromised, an attacker can use precomputed rainbow tables to recover token values. The same token always produces the same hash, making bulk attacks efficient.

- `control_plane/services/backend/control_plane/crypto.py:28-30`

**Recommendation:** Use a purpose-built key derivation function (bcrypt, scrypt, or Argon2id) with per-token salt.

### 3. Auth tokens stored in localStorage

The frontend stores bearer tokens in `localStorage`, which is accessible to any JavaScript running on the same origin. A single XSS vulnerability would allow an attacker to exfiltrate the token silently.

- `control_plane/services/frontend/src/api/client.ts:75-85`

**Recommendation:** Use `httpOnly` secure cookies for token transport, or at minimum move to `sessionStorage`.

### 4. Credentials passed via container environment variables

Credentials such as `STATIC_CREDENTIALS`, database passwords, and API tokens are injected as environment variables in Docker Compose. These are visible in `docker inspect`, `/proc/<pid>/environ`, and core dumps. Any container escape or debug access exposes them.

- `data_plane/docker-compose.yml:446-454` (email proxy secrets)
- `control_plane/docker-compose.yml:35,39` (DATABASE_URL, ENCRYPTION_KEY)
- Lua filter reads `STATIC_CREDENTIALS` at `data_plane/configs/envoy/filter.lua:37-44`

**Recommendation:** Use Docker secrets or a secrets manager (Vault, SOPS) instead of environment variables for production deployments.

### 5. Docker socket mounted in data plane containers

Three services mount `/var/run/docker.sock` (read-only): log-shipper, agent-manager, and local-admin. Even read-only access allows full container enumeration and inspection, and is a well-documented privilege escalation vector. A compromised service on `infra-net` could inspect all containers, read their environment variables (including secrets), and potentially escape to the host.

- `data_plane/docker-compose.yml:313` (log-shipper)
- `data_plane/docker-compose.yml:378` (agent-manager)
- `data_plane/docker-compose.yml:415` (local-admin)

**Recommendation:** Use the Docker API over TCP with TLS client certs and restricted permissions, or use a socket proxy that filters allowed API calls.

---

## Medium

### 6. Tunnel client bridges agent-net and infra-net

When the `ssh` profile is active, the FRP tunnel client is attached to both `agent-net` (10.200.1.30) and `infra-net` (10.200.2.30). A compromised tunnel client could route traffic between the isolated agent network and the infrastructure network, breaking the core isolation boundary.

- `data_plane/docker-compose.yml:500-507`

**Recommendation:** Remove the tunnel client from `agent-net` and proxy SSH access through a dedicated service on `infra-net` only.

### 7. Permissive seccomp profile defeats sandboxing

The `permissive.json` seccomp profile uses `SCMP_ACT_ALLOW` as the default action, only blocking raw sockets. This effectively disables seccomp and allows the agent container to invoke arbitrary syscalls including those needed for container escape (ptrace, mount, unshare, setns).

- `data_plane/configs/seccomp/profiles/permissive.json`

**Recommendation:** Remove the permissive profile entirely, or gate it behind a prominent warning and never reference it from default compose configurations.

### 8. gVisor standard profile disables host seccomp

When running under gVisor (`standard` profile), the agent container sets `seccomp:unconfined`, relying entirely on gVisor's user-space syscall interception. If a gVisor sandbox escape occurs, no host seccomp profile exists as a fallback layer.

- `data_plane/docker-compose.yml:154`

**Recommendation:** Apply a host-level seccomp profile alongside gVisor to provide defense-in-depth.

### 9. In-memory Lua rate limiting resets on Envoy restart

The Lua filter's token-bucket rate limiter stores all state in the Lua VM's memory. An Envoy restart (crash, config reload, deployment) resets all rate limit windows, allowing a burst of previously-limited requests.

- `data_plane/configs/envoy/filter.lua:13` (token_buckets table)
- `data_plane/configs/envoy/filter.lua:390-420` (rate limit function)

**Recommendation:** Back rate limit state with Redis or Envoy's built-in `envoy.filters.http.ratelimit` service with an external rate limit server.

### 10. No credential or key rotation mechanism

There is no tooling or process for rotating the Fernet `ENCRYPTION_KEY`, API tokens, database credentials, or FRP tunnel secrets. A compromised key requires manual intervention across all services.

- `control_plane/services/backend/control_plane/crypto.py:9` (ENCRYPTION_KEY loaded once at startup)

**Recommendation:** Implement key rotation support (dual-key decryption during transition) and document a rotation runbook.

---

## Low

### 11. WebSocket ticket passed as query parameter

Terminal access tickets are sent as a `?ticket=` query parameter during the WebSocket handshake. Query parameters may appear in access logs, load balancer logs, and HTTP `Referer` headers. The ticket is single-use and expires in 60 seconds, which limits the exposure window.

- `control_plane/services/backend/control_plane/routes/terminal.py:125`

**Recommendation:** Document the log-scrubbing requirement for any reverse proxy in front of the backend. Consider a two-step upgrade where the ticket is sent in the first WebSocket message instead.

### 12. DNS tunneling detection is heuristic-only

The Lua filter detects DNS tunneling via label length, hostname length, subdomain depth, and hex-pattern heuristics. These can be evaded with short labels, mixed encoding, or slow exfiltration over many queries.

- `data_plane/configs/envoy/filter.lua:136-170`

**Recommendation:** Supplement heuristics with per-domain query volume anomaly detection and consider integrating a dedicated DNS analytics tool.
