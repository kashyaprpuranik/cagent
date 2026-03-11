# Cagent

Secure development and execution environment for AI agents with isolated networking.

## Problem

AI agents need network access to be useful—fetching documentation, calling APIs, installing packages. But unrestricted access creates serious risks:

- **Data exfiltration**: Agent sends proprietary code or leaks secrets (credential theft) to unauthorized endpoints. Example: [Google's Gemini exfiltrating data via markdown image rendering](https://www.promptarmor.com/resources/google-antigravity-exfiltrates-data)
- **Supply chain attacks**: Agent installs malicious packages, compromised plugins, or executes untrusted code. Example: [Hundreds of malicious MCP skills discovered in ClawHub](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/)
- **Runaway costs**: Agent makes unlimited API calls, racking up unexpected bills
- **Lateral movement**: Compromised agent pivots to internal services

The core tension: agents need enough access to work, but not so much that a misaligned or compromised agent can cause damage.

## Threat Model

Cagent assumes the AI agent is **untrusted by default**. The agent may be:

| Threat | Description |
|--------|-------------|
| **Misaligned** | Pursues goals that don't match user intent (prompt injection, jailbreak) |
| **Compromised** | Executes malicious code from a poisoned dependency or hostile input |
| **Overly capable** | Has access to credentials/APIs it shouldn't, even if behaving correctly |
| **Unpredictable** | Makes unexpected network requests due to hallucination or bugs |

## Security Principles

| Principle | Description |
|-----------|-------------|
| **Network Isolation** | Cell can only reach proxy (Envoy or mitmproxy) and CoreDNS (DNS filter) - no direct internet access |
| **Credential Hiding** | Cell never sees API keys; credentials injected by proxy at egress |
| **Defense in Depth** | Multiple layers: network, container, optional kernel (gVisor) isolation |
| **Least Privilege** | Minimal capabilities, read-only filesystem, resource limits |
| **Audit Everything** | All HTTP requests, DNS queries, and syscalls logged |

## Hardening Details

### Container Security
| Control | Implementation |
|---------|----------------|
| No privilege escalation | `no-new-privileges` security option |
| Seccomp profile | Blocks raw sockets (prevents packet-crafting bypass) |
| Resource limits | CPU, memory, PID limits enforced |
| Forced proxy | `HTTP_PROXY`/`HTTPS_PROXY` environment variables |
| Forced DNS | Container DNS set to CoreDNS filter IP |

### Network Security
| Control | Implementation |
|---------|----------------|
| Internal network | `cell-net` marked as `internal: true` (no default gateway) |
| Protocol restriction | Cell can ONLY reach Envoy (HTTP), mitmproxy (HTTPS), and CoreDNS (DNS) |
| IPv6 disabled | Prevents bypass of IPv4 egress controls |
| Allowlist enforcement | CoreDNS blocks resolution of non-allowed domains |
| Egress proxy | All HTTP routed through Envoy; HTTPS through mitmproxy → Envoy |
| Raw socket blocked | Seccomp profile prevents packet crafting |

**Protocol Smuggling Prevention**: Raw TCP/UDP to external hosts is impossible. The cell can only reach a few IPs on the internal network: Envoy (port 8443, HTTP), mitmproxy (port 8080, HTTPS), and CoreDNS (port 53, DNS). Seccomp blocks raw socket creation (AF_PACKET), preventing packet crafting.

**Residual Exfiltration Channels**: Small amounts of data could theoretically be exfiltrated via DNS queries or HTTPS traffic to allowlisted domains. Mitigations: DNS tunneling detection (blocks long subdomains) and audit logging.

**Defense in Depth**: Network isolation doesn't depend solely on Envoy/CoreDNS being healthy. The `internal: true` network flag removes the default gateway at the Docker level.

### Kernel Isolation (gVisor)

The `standard` profile uses [gVisor](https://gvisor.dev) to intercept syscalls in user-space. This is the recommended default for production.

| Control | Implementation |
|---------|----------------|
| gVisor runtime | `runsc` - syscalls never reach host kernel |
| Stricter limits | 1 CPU, 2GB memory |

### Credential Security
| Control | Implementation |
|---------|----------------|
| Injection at proxy | Envoy ext_authz filter injects credentials at egress |
| Short-lived cache | Credentials cached for 5 minutes |

## Quick Start

### Standalone Mode

Run with local configuration - ideal for local use of one cell.

#### Minimal (Static Config)

Lightweight setup with just 3 containers. Edit `cagent.yaml` and run the config generator, or edit raw `coredns/Corefile` and `envoy/envoy.yaml` directly for advanced use. Ideal for simple static domain policies on one cell.

```
┌─────────────────────────────────────────────────────┐
│                 cell-net (isolated)                  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │                     Cell                      │  │
│  │  - Isolated network (no direct internet)      │  │
│  │  - All HTTP(S) via HTTP Proxy                 │  │
│  │  - DNS via DNS Filter                         │  │
│  └───────────────────────────────────────────────┘  │
│                │                   │                 │
│                ▼                   ▼                 │
│         ┌───────────┐       ┌───────────┐           │
│         │HTTP Proxy │       │DNS Filter │           │
│         │  (~50MB)  │       │  (~20MB)  │           │
│         └───────────┘       └───────────┘           │
└─────────────────────────────────────────────────────┘
```

```bash
# Recommended: with gVisor (requires installation: https://gvisor.dev/docs/user_guide/install/)
docker compose --profile standard up -d

# Development: without gVisor (if not installed)
docker compose --profile dev up -d
```

#### Locally Managed (With Admin UI)

Adds warden (watches `cagent.yaml`) and local admin UI for browser-based management and observability. Ideal for complex and changing domain policies on one cell.

```
┌───────────────────────────────────────────────────────────────┐
│                          DATA PLANE                           │
│                                                               │
│  ┌──────────────────────────────────────────┐                 │
│  │       Warden (:8081)                     │                 │
│  │  - Admin UI (config, terminal, logs)     │                 │
│  │  - Watches cagent.yaml, regenerates      │                 │
│  │    DNS filter + HTTP proxy configs       │                 │
│  └──────────────┬───────────────────────────┘                 │
│                 │                                              │
│  ┌──────────────┼──────────────────────────────────────────┐  │
│  │              │         cell-net (isolated)               │  │
│  │    ┌─────────┴────────────────────────────────────┐     │  │
│  │    │                    Cell                       │     │  │
│  │    └──────────────────────────────────────────────┘     │  │
│  │          │             │                │               │  │
│  │   ┌──────┴──────┐ ┌───┴────────┐ ┌─────┴───────┐      │  │
│  │   │ MITM Proxy  │ │ HTTP Proxy │ │ DNS Filter  │      │  │
│  │   │ (HTTPS TLS) │ │ (controls) │ │ (allowlist) │      │  │
│  │   └─────────────┘ └────────────┘ └─────────────┘      │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

```bash
# Recommended: with gVisor (requires installation)
docker compose --profile standard --profile admin up -d

# Development: without gVisor
docker compose --profile dev --profile admin up -d
```

**Admin UI** (http://localhost:8081):
- Structured config editor (domains, rate limits, credentials)
- Container status with health checks
- Log viewer with traffic analytics
- Browser-based web terminal

#### Locally Managed with Auditing

Adds log collection and a local log store for standalone deployments. Vector collects logs from all containers and ships them to OpenObserve (local log analytics) and local files. The warden queries OpenObserve for the traffic analytics dashboard. Configure additional sinks (S3, Elasticsearch) in `configs/vector/sinks/standalone.yaml`.

```
┌───────────────────────────────────────────────────────────────────┐
│                           DATA PLANE                               │
│                                                                    │
│  ┌──────────────────────────┐  ┌────────────┐  ┌───────────────┐  │
│  │   Warden (:8081)         │  │Log Shipper │  │  Log Store    │  │
│  │   admin UI, config sync  │  │  (Vector)  │─►│ (OpenObserve) │  │
│  │                          │  │            │  │  30d retention │  │
│  │   queries log store ────────────────────────►│               │  │
│  └──────────────┬───────────┘  │  also ──►file │  │  │
│                 │              └────────────┘  └───────────────┘  │
│  ┌──────────────┼──────────────────────────────────────────────┐  │
│  │              │         cell-net (isolated)                   │  │
│  │    ┌─────────┴────────────────────────────────────┐         │  │
│  │    │                    Cell                       │         │  │
│  │    └──────────────────────────────────────────────┘         │  │
│  │          │             │                │                    │  │
│  │   ┌──────┴──────┐ ┌───┴────────┐ ┌─────┴───────┐          │  │
│  │   │ MITM Proxy  │ │ HTTP Proxy │ │ DNS Filter  │          │  │
│  │   └─────────────┘ └────────────┘ └─────────────┘          │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  Optional:                                                         │
│  ┌──────────────────────────────────────────┐                      │
│  │      Email Proxy (:8025) - beta          │                      │
│  │  - IMAP/SMTP with per-recipient policy   │                      │
│  └──────────────────────────────────────────┘                      │
└───────────────────────────────────────────────────────────────────┘
```

```bash
# With auditing (log collection + local log store)
docker compose --profile dev --profile admin --profile auditing up -d

# With email proxy (beta)
docker compose --profile dev --profile admin --profile auditing --profile email up -d
```

#### Multiple Cells

Run multiple isolated cells on the same data plane. Each cell gets its own container with independent network isolation, sharing the same proxy, DNS filter, and policy configuration.

```bash
# 3 cells with admin UI and auditing
docker compose --profile dev --profile admin --profile auditing up -d --scale cell-dev=3
```

Cells are named `cagent-cell-dev-1`, `cagent-cell-dev-2`, etc. All share the same `cell-net` network and are subject to the same domain allowlist, rate limits, and credential injection policies.

**Accessing the Cell**

| Method | How |
|--------|-----|
| **Web Terminal** | http://localhost:8081 (admin UI) |
| **Docker exec** | `docker exec -it cell bash` |
| **SSH** | Direct SSH to port 2222 (configure via admin UI) |

### Connected Mode

For centralized management of multiple data planes, connect to a [control plane](https://github.com/kashyaprpuranik/cagent-control). Connected mode adds:

- **Centralized policy management** — domain policies, security profiles, and credentials managed from a single admin UI
- **Multi-tenant isolation** — multiple teams share one control plane with full tenant isolation
- **Remote cell management** — start, stop, restart, and wipe cells from the control plane
- **Centralized log querying** — the control plane queries each DP's local OpenObserve via warden for traffic analytics
- **OAuth authentication** — GitHub/Google login, API tokens, and IP ACL enforcement

```
                                  ┌──────────────────────────────┐
                                  │        Control Plane          │
                                  │                               │
                                  │  Admin UI ── API ── Postgres  │
                                  │               │               │
                                  └───────────────┼───────────────┘
                                                  │
                          heartbeat/poll (outbound)│log queries (inbound
                          config sync              │  via mTLS)
                                                  │
┌─────────────────────────────────────────────────┼──────────────────┐
│                         DATA PLANE              │                   │
│                                                 │                   │
│  ┌──────────────────────────┐                   │                   │
│  │   Warden                 │◄──────────────────┘                   │
│  │   config sync, heartbeat │                                       │
│  │                          │  ┌────────────┐  ┌───────────────┐   │
│  │   queries log store ───────────────────────►│  Log Store    │   │
│  │                          │  │Log Shipper │─►│ (OpenObserve) │   │
│  └──────────────┬───────────┘  │  (Vector)  │  │  30d retention │   │
│                 │              │  also ──►file │               │   │
│  ┌──────────────┼─────────────┘────────────┘  └───────────────┘   │
│  │              │         cell-net (isolated)                       │
│  │    ┌─────────┴────────────────────────────────────┐             │
│  │    │                    Cell                       │             │
│  │    └──────────────────────────────────────────────┘             │
│  │          │             │                │                        │
│  │   ┌──────┴──────┐ ┌───┴────────┐ ┌─────┴───────┐              │
│  │   │ MITM Proxy  │ │ HTTP Proxy │ │ DNS Filter  │              │
│  │   └─────────────┘ └────────────┘ └─────────────┘              │
│  └─────────────────────────────────────────────────────────────────┘
└────────────────────────────────────────────────────────────────────┘
```

All connections from DP to CP are outbound — no inbound ports needed on the data plane. Log queries from the CP to warden use mTLS.

```bash
# Connected mode
CONTROL_PLANE_URL=https://api.example.com CONTROL_PLANE_TOKEN=your-agent-token \
docker compose --profile dev --profile managed --profile auditing up -d
```

## Features

| Feature | Description |
|---------|-------------|
| **Domain Allowlist** | Only approved domains can be accessed (enforced by CoreDNS and Envoy) |
| **HTTPS Interception** | MITM proxy decrypts HTTPS so all controls apply to encrypted traffic |
| **Credential Injection** | API keys injected by proxy, never exposed to cell (works for both HTTP and HTTPS) |
| **Rate Limiting** | Per-domain rate limits to control API usage |
| **Traffic Analytics** | Requests/sec, top domains, error rates in log viewer |
| **Web Terminal** | Browser-based shell access to cells (xterm.js) |
| **gVisor Isolation** | Optional kernel-level syscall isolation for defense in depth |
| **Email Proxy** | Controlled IMAP/SMTP access with per-recipient policies - **beta** |

## Configuration

See [docs/configuration.md](docs/configuration.md) for detailed configuration including:
- Domain policies (allowlist, path filtering, rate limits, egress limits, credentials)
- Cell management commands
- Per-cell configuration (cell-specific domain policies)

## Documentation

- [Configuration Guide](docs/configuration.md) - Domains, rate limits, credentials, path filtering

## Roadmap

- [ ] Improved secret management in standalone mode (encrypted local storage)
- [ ] Alert rules for security events (gVisor syscall denials, rate limit hits)
- [ ] Per-path rate limits and credential injection (path-level policies within a domain)
- [ ] Prompt injection protection (detect and block injected instructions in agent inputs/outputs)

## License

MIT
