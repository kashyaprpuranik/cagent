# Pingora Migration: Unified Data Plane Proxy

Replace Envoy + mitmproxy + CoreDNS with a single Rust binary using Pingora + Hickory DNS.

## Current Architecture

```
Cell → CoreDNS (DNS, 32MB) → upstream DNS
Cell → mitmproxy (HTTPS, 80MB) → Envoy → warden ext_authz → Envoy → Internet
Cell → Envoy (HTTP, 80MB) → warden ext_authz → Envoy → Internet
```

3 processes, ~350MB total, multiple network hops, ext_authz round-trip per request.

## Target Architecture

```
Cell → cagent-proxy (HTTP/HTTPS/DNS, ~20-50MB) → Internet
         ↑
       Warden (config sync only, no ext_authz)
```

1 process, credentials + allowlist + DLP embedded in-process.

## Decision: Pingora + Hickory DNS

**Why Pingora over Rama:** Pingora is battle-tested at Cloudflare scale (~26K stars, production). Rama has first-class MITM but is alpha (~982 stars). For a core security component, maturity wins.

**Why not Pingora's ProxyHttp trait:** It doesn't support CONNECT (forward proxy). We use `pingora-core`'s `ServerApp` trait directly for raw stream access, handling CONNECT + MITM ourselves.

**Why Hickory DNS:** The only mature embeddable DNS server in Rust (~5K stars). Custom `RequestHandler` trait maps directly to our allowlist filtering.

## Crate Stack

| Component | Crate | Role |
|-----------|-------|------|
| Core framework | `pingora-core` | Event loop, connection mgmt, graceful shutdown |
| MITM TLS | `tokio-rustls` | TLS accept on intercepted connections |
| Cert generation | `rcgen` | Dynamic per-domain cert signing by MITM CA |
| Cert cache | `moka` | Async LRU cache (~1000 domains, TTL-based) |
| Config hot-reload | `arc-swap` | Lock-free atomic config swapping |
| DLP prefix scan | `aho-corasick` | Fast multi-pattern literal matching (SIMD) |
| DLP regex validation | `regex` | Pattern validation after prefix match |
| Credential storage | `secrecy` + `zeroize` | Secure in-memory secret handling |
| HTTP parsing | `hyper` or `httparse` | Parse decrypted HTTP from MITM stream |
| DNS server | `hickory-server` | Embedded DNS filtering |
| Cross-compilation | `cross` (tool) | ARM builds for Hetzner cax11 |

## Implementation Phases

### Phase 1: HTTP Forward Proxy (1 week)

Implement `ServerApp` on `pingora-core`:
- Accept TCP connections
- Parse HTTP requests (non-CONNECT)
- Domain allowlist check (reject → 403, allow → proxy upstream)
- Rate limiting per domain
- Credential injection (add Authorization header before proxying)
- Config via `arc-swap` (domain allowlist, credentials, rate limits)

Replaces: Envoy (for HTTP) + warden ext_authz

### Phase 2: MITM HTTPS Proxy (1 week)

Add CONNECT handling:
- Accept CONNECT, respond 200, get raw stream
- Generate per-domain cert signed by MITM CA (`rcgen`)
- TLS accept with `tokio-rustls` using generated cert
- Cache certs in `moka` LRU
- Parse decrypted HTTP, apply same filters as Phase 1
- DLP body scanning (`aho-corasick` prefix + `regex` validation)

Replaces: mitmproxy + Envoy (for HTTPS)

### Phase 3: DNS Filtering (3 days)

Embed `hickory-server`:
- Custom `RequestHandler` that checks domain against allowlist
- Allowed → forward to upstream DNS resolver
- Blocked → return NXDOMAIN
- Share allowlist config with proxy via `arc-swap`

Replaces: CoreDNS

### Phase 4: Config Sync + Warden Integration (3 days)

- HTTP endpoint for config push from warden
- Accept JSON: domain allowlist, credentials, rate limits, DLP patterns
- Atomic swap via `arc-swap`
- Warden modified to push config to cagent-proxy instead of writing Corefile/Envoy config and restarting services

### Phase 5: Docker Image + Integration (2-3 days)

- Dockerfile for cagent-proxy (Rust binary, ~20-50MB)
- Cross-compile for ARM (aarch64) and x86
- Update docker-compose.yml: replace envoy + mitmproxy + coredns with cagent-proxy
- Update cell DNS config to point to cagent-proxy
- Update cell HTTP_PROXY/HTTPS_PROXY to point to cagent-proxy
- E2E tests

## Total Effort: 4-5 weeks

- Phase 1-2 (proxy): 2 weeks — bulk of the work
- Phase 3 (DNS): 3 days
- Phase 4 (config): 3 days
- Phase 5 (integration): 2-3 days
- Testing + edge cases: 1 week

## Key Challenges & Solutions

### Forward Proxy / CONNECT
Pingora's `ProxyHttp` trait rejects CONNECT. Solution: use `ServerApp` directly on `pingora-core` for raw stream access. Sidesteps the proxy layer entirely.

### MITM Certificate Generation
Pattern from Hudsucker/Privaxy: `rcgen` generates per-domain certs signed by MITM CA, cached in `moka` LRU. `tokio-rustls` accepts TLS on the intercepted stream.

### Config Hot-Reload
`arc-swap` for lock-free atomic config swapping. Warden pushes config via HTTP endpoint. No restart needed.

### DLP Body Scanning
Two-phase: `aho-corasick` for fast prefix matching (`AKIA`, `ghp_`, `-----BEGIN`), `regex` for validation. Linear time, SIMD-accelerated.

### Credential Security
`secrecy` + `zeroize` crates. Memory zeroed on drop. Combined with `arc-swap` for runtime credential updates without restart.

### ARM Cross-Compilation
Use `tokio-rustls` (pure Rust) for MITM layer — trivial cross-compile. Target `aarch64-unknown-linux-gnu` for Hetzner cax11. Avoid BoringSSL's C toolchain.

## Benefits

| Metric | Current | After Migration |
|--------|---------|-----------------|
| Processes | 3 (Envoy + mitmproxy + CoreDNS) | 1 (cagent-proxy) |
| Memory | ~350MB | ~20-50MB |
| Latency | mitmproxy → Envoy → ext_authz → Envoy | Single process, no IPC |
| Config reload | Restart Envoy + CoreDNS | Atomic in-memory swap |
| ext_authz calls | Per-request to warden | None (credentials embedded) |
| Languages | Go (CoreDNS) + Python (mitmproxy) + C++ (Envoy) | Rust |

## Feature Parity Checklist

### Envoy Features

| Feature | Current (Envoy) | cagent-proxy | Status |
|---------|----------------|--------------|--------|
| HTTP forward proxy (port 8443) | Envoy listener | hyper listener (18443) | ✅ Phase 1 |
| Domain allowlist (virtual hosts) | Generated YAML | In-memory HashSet | ✅ Phase 1 |
| Path filtering (allowed_paths) | Per-route config | In-memory check | ✅ Phase 1 |
| Read-only enforcement (block POST/PUT/DELETE) | Header matching routes | Method check | ✅ Phase 1 |
| Credential injection | ext_authz → warden round-trip | In-process (arc-swap) | ✅ Phase 1 |
| Config hot-reload | Restart Envoy / xDS file watch | arc-swap atomic swap | ✅ Phase 1 |
| TLS upstream (re-encrypt to origin) | Cluster transport_socket | hyper-rustls | ✅ Phase 2 |
| Access logging (JSON to stdout) | Access log config | tracing (structured) | ✅ Phase 1 |
| Admin API (stats, health) | localhost:9901 | /health endpoint | ✅ Phase 1 |
| Catch-all 403 (unlisted domains) | Default virtual host | Default deny | ✅ Phase 1 |
| Rate limiting (per-domain RPM) | local_ratelimit filter, token bucket | TODO | Phase 1b |
| Devbox.local aliases (rewrite Host) | Virtual host + auto_host_rewrite | alias field + Host rewrite | ✅ Phase 1b |
| Timeout enforcement (30s) | Per-route/cluster timeouts | tokio::time::timeout | ✅ Phase 1b |
| Metadata IP block (169.254.169.254) | Virtual host 403 | Pre-allowlist check | ✅ Phase 1b |
| X-Real-Domain header | Request header add | Added to upstream req | ✅ Phase 1b |
| X-Credential-Injected header | ext_authz response | Added after injection | ✅ Phase 1b |
| Shared HTTP client (connection pooling) | Implicit via circuit breakers | LazyLock\<Client\> | ✅ Phase 1b |
| Rate limiting (per-domain RPM) | local_ratelimit filter, token bucket | Token bucket per domain | ✅ Phase 1b |
| Circuit breakers (max connections) | Per-cluster config | TODO | Future |
| Retry logic | Per-route retry_policy | TODO | Future |
| Email proxy routing (email.devbox.local) | Virtual host → email-proxy | TODO | Future |

### mitmproxy Features

| Feature | Current (mitmproxy) | cagent-proxy | Status |
|---------|--------------------|--------------| --------|
| TLS interception (MITM) | --mode regular | tokio-rustls + rcgen | ✅ Phase 2 |
| Per-domain cert generation | Built-in CA | rcgen + moka cache | ✅ Phase 2 |
| HTTPS → HTTP redirect to Envoy | mitm_addon.py | Not needed (single process) | ✅ N/A |
| Lazy connection strategy | --set connection_strategy=lazy | Default (connect on demand) | ✅ N/A |
| DLP pattern scanning | dlp_addon.py (regex) | aho-corasick prefix + regex | ✅ Phase 2b |
| DLP modes (log/block/redact) | dlp_config.json | In-memory config | ✅ Phase 2b |
| DLP base64 decoding | Built-in | base64 crate decode + re-scan | ✅ Phase 2b |
| DLP skip_domains | Config list | In-memory skip set | ✅ Phase 2b |
| DLP threshold patterns (email/phone bulk) | Count-based | find_iter count >= threshold | ✅ Phase 2b |
| Body scan size limit (1MB) | --set stream_large_bodies=1m | Truncate to 1MB before scan | ✅ Phase 2b |
| Upstream cert skip | --set upstream_cert=false | Uses webpki-roots (standard verify) | ✅ Phase 2 |

### CoreDNS Features

| Feature | Current (CoreDNS) | cagent-proxy | Status |
|---------|-------------------|--------------| --------|
| Domain allowlist (forward allowed) | Corefile per-domain blocks | In-memory HashSet | ✅ Phase 3 |
| NXDOMAIN for blocked domains | Catch-all template | Return NXDOMAIN | ✅ Phase 3 |
| Upstream forwarding (8.8.8.8) | forward plugin | UDP forward to 8.8.8.8/8.8.4.4 | ✅ Phase 3 |
| Devbox.local → proxy IP | template plugin | Custom A record (proxy cell-net IP) | ✅ Phase 3 |
| IPv6 AAAA suppression | template NOERROR | Return empty AAAA | ✅ Phase 3 |
| Hot-reload | reload plugin (5s) | arc-swap (instant via config push) | ✅ Phase 4 |
| Query logging | log plugin | tracing | ✅ Phase 3 |
| HA failover (dns-filter-2) | --profile dns-ha | Not needed (embedded) | ✅ N/A |
| Health check (:8080) | health plugin | /health on config API | ✅ Phase 1 |
| DNS caching (configurable TTL) | cache plugin | TODO | Future |
| Email proxy DNS (Docker internal) | forward to 127.0.0.11 | TODO | Future |

### Warden Integration Changes

| Feature | Current | After Migration | Status |
|---------|---------|-----------------|--------|
| Config delivery | Generate Corefile + Envoy YAML, restart services | POST /config JSON, arc-swap | ✅ Phase 4 |
| Credential delivery | ext_authz HTTP call per request | Embedded in config, in-process | ✅ Phase 4 |
| Service restarts | docker restart coredns, envoy | None needed (atomic config swap) | ✅ Phase 4 |
| DLP config | Write dlp_config.json, mitmproxy re-reads | Included in /config JSON push | ✅ Phase 2b |

## Backwards Compatibility

The new proxy runs alongside the existing stack via Docker Compose profiles. No breaking changes until the migration is proven.

### Dual-Stack Approach

```yaml
# docker-compose.yml — existing services unchanged
http-proxy:     # Envoy, profiles: [dev, standard]
mitm-proxy:     # mitmproxy, profiles: [dev, standard]
dns-filter:     # CoreDNS, profiles: [dev, standard]

# New service, opt-in profile
cagent-proxy:
  profiles: ["proxy-rust"]
  image: ghcr.io/.../cagent-proxy:latest
  networks:
    cell-net:
      ipv4_address: 10.${NET_OCTET:-200}.1.20  # same subnet, new IP
    infra-net:
      ipv4_address: 10.${NET_OCTET:-200}.2.20
  ports:
    - "8053:53/udp"   # DNS
    - "8053:53/tcp"
```

### Toggle Mechanism

`PROXY_MODE` env var (default: `legacy`):

- **`legacy`** (default): Cell uses Envoy + mitmproxy + CoreDNS. Warden writes Corefile + Envoy config, restarts services. No change from today.
- **`rust`**: Cell uses cagent-proxy. Warden pushes config via HTTP to cagent-proxy. Cell's `HTTP_PROXY`, `HTTPS_PROXY`, and DNS point to cagent-proxy IPs.

### Migration Path

1. **Phase 1-4**: Build and test cagent-proxy with `--profile proxy-rust`. Legacy stack still default.
2. **Phase 5**: Run both stacks in parallel on test cells. Compare behavior.
3. **Phase 6**: Switch default to `rust`. Legacy services still available via `--profile legacy`.
4. **Phase 7**: Remove legacy services after production validation.

### Warden Changes

Warden detects `PROXY_MODE` and:
- `legacy`: generates Corefile + Envoy YAML, restarts CoreDNS + Envoy (today's behavior)
- `rust`: POSTs config JSON to `http://cagent-proxy:8080/config` (domain allowlist, credentials, rate limits, DLP patterns)

Both paths use the same source data (CP domain policies, credentials). Only the delivery mechanism differs.

## References

- [Pingora GitHub](https://github.com/cloudflare/pingora) — 26K stars, v0.8.0
- [Hickory DNS](https://github.com/hickory-dns/hickory-dns) — 5K stars
- [rcgen](https://github.com/rustls/rcgen) — cert generation
- [moka](https://github.com/moka-rs/moka) — async LRU cache
- [arc-swap](https://docs.rs/arc-swap) — lock-free config swap
- [Hudsucker](https://github.com/omjadas/hudsucker) — Rust MITM proxy (reference impl)
- [Privaxy](https://github.com/Barre/privaxy) — Rust MITM proxy (reference impl)
- [http-mitm-proxy](https://github.com/hatoo/http-mitm-proxy) — lightweight MITM crate
- [Pingora Issue #224](https://github.com/cloudflare/pingora/issues/224) — forward proxy discussion
- [Pingora Issue #230](https://github.com/cloudflare/pingora/issues/230) — raw stream access
