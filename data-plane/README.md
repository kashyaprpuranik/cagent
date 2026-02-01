# AI Devbox - Data Plane

The data plane provides a secure, isolated execution environment for AI agents with controlled network egress, credential injection, and audit logging.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Data Plane                                │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    agent-net (isolated)                  │    │
│  │  ┌─────────┐                                            │    │
│  │  │  Agent  │ ──HTTP──► ┌───────────┐                    │    │
│  │  │Container│           │   Envoy   │ ──HTTPS──► Internet│    │
│  │  └─────────┘ ──DNS───► │   Proxy   │                    │    │
│  │       │                └───────────┘                    │    │
│  │       │                      │                          │    │
│  │       └──────► ┌─────────────┴───┐                      │    │
│  │                │   DNS Filter    │                      │    │
│  │                │   (CoreDNS)     │                      │    │
│  │                └─────────────────┘                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    infra-net                             │    │
│  │  ┌───────────┐                                          │    │
│  │  │ Fluent-Bit│ ──────────────────────────► Loki         │    │
│  │  │  (logs)   │                             (direct)     │    │
│  │  └───────────┘                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Envoy ──► Control Plane API (credentials, rate limits)         │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Network Isolation**: Agent container can only reach Envoy proxy and DNS filter
- **Domain Allowlist**: DNS filtering blocks unapproved domains
- **Credential Injection**: Automatic API key injection via `*.devbox.local` aliases
- **Rate Limiting**: Per-domain rate limits with token bucket algorithm
- **Audit Logging**: All requests logged with optional forwarding to Loki
- **Standalone Mode**: Run without control plane using static configuration

## Control Plane API

When running in connected mode, the data plane communicates with the control plane API for:
- Credential lookups (`/api/v1/secrets/for-domain`) - includes domain alias mappings
- Rate limit configuration (`/api/v1/rate-limits/for-domain`)
- Allowlist export (`/api/v1/allowlist/export`)
- Agent heartbeat (`/api/v1/agent/heartbeat`)

The control plane API (FastAPI) auto-generates OpenAPI docs:
- Swagger UI: `http://localhost:8002/docs`
- ReDoc: `http://localhost:8002/redoc`

## Quick Start

### Connected Mode (with Control Plane)

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env: set CONTROL_PLANE_TOKEN

# Start data plane with auditing
docker-compose --profile auditing up -d
```

### Standalone Mode (no Control Plane)

```bash
# Copy and configure environment
cp .env.example .env

# Edit .env:
#   DATAPLANE_MODE=standalone
#   STATIC_DOMAIN_MAP=openai.devbox.local:api.openai.com
#   STATIC_CREDENTIALS=api.openai.com:Authorization:Bearer sk-your-key
#   STATIC_RATE_LIMITS=default:120:20

# Start data plane (no auditing)
docker-compose up -d
```

### Using YAML Configuration

```bash
# Edit configs/static-config.yaml with your settings
# Then load and start:
eval $(scripts/load-static-config.sh --export)
docker-compose up -d
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_ID` | `default` | Unique identifier for this data plane |
| `AGENT_VARIANT` | `lean` | Agent image variant: `lean`, `dev`, or `ml` |
| `DATAPLANE_MODE` | `connected` | `standalone` or `connected` |
| `CONTROL_PLANE_TOKEN` | (none) | API token for control plane auth |
| `CONTROL_PLANE_URL` | `http://control-plane-api:8000` | Control plane URL |
| `HEARTBEAT_INTERVAL` | `30` | Seconds between heartbeats to control plane |
| `LOKI_HOST` | (required for auditing) | Loki host IP/hostname for log shipping |
| `LOKI_PORT` | `3100` | Loki port |
| `STATIC_DOMAIN_MAP` | (none) | Devbox.local domain mappings |
| `STATIC_CREDENTIALS` | (none) | Static credentials for injection |
| `STATIC_RATE_LIMITS` | `default:120:20` | Rate limits per domain |
| `AGENT_CONTAINER_NAME` | `agent` | Container name for agent |
| `AGENT_WORKSPACE_VOLUME` | `data-plane_agent-workspace` | Volume name for agent workspace |
| `SSH_AUTHORIZED_KEYS` | (none) | SSH public keys for agent access |
| `FRP_SERVER_ADDR` | (required for ssh) | FRP server address (control plane host) |
| `FRP_AUTH_TOKEN` | (required for ssh) | FRP authentication token |
| `FRP_REMOTE_PORT` | `6000` | Remote port for SSH tunnel (unique per agent) |
| `ENVIRONMENT` | `development` | Environment name for logging |

### Static Configuration Formats

**Domain Mappings** (`STATIC_DOMAIN_MAP`):
```
alias.devbox.local:real-domain.com,another.devbox.local:api.example.com
```

**Credentials** (`STATIC_CREDENTIALS`):
```
domain:header_name:header_value|domain2:header_name:header_value
```
Example:
```
api.openai.com:Authorization:Bearer sk-xxx|api.github.com:Authorization:token ghp-xxx
```

**Rate Limits** (`STATIC_RATE_LIMITS`):
```
domain:requests_per_minute:burst_size,domain2:rpm:burst
```
Example:
```
default:120:20,api.openai.com:60:10,api.github.com:100:15
```

### YAML Configuration

Edit `configs/static-config.yaml`:

```yaml
domain_mappings:
  openai.devbox.local: api.openai.com
  github.devbox.local: api.github.com

credentials:
  - domain_pattern: "api.openai.com"
    header_name: "Authorization"
    header_value: "Bearer sk-your-key"

rate_limits:
  default:
    requests_per_minute: 120
    burst_size: 20
  domains:
    "api.openai.com":
      requests_per_minute: 60
      burst_size: 10
```

Load with: `eval $(scripts/load-static-config.sh --export)`

## Operation Modes

### Connected Mode (default)

Requires a running control plane. Features:

| Feature | Source |
|---------|--------|
| Credentials | Control plane API (with local cache) |
| Rate limits | Control plane API (with local cache) |
| Domain allowlist | Synced from control plane every 5 min |
| Domain aliases | Control plane (via secret aliases) |
| Agent management | Heartbeat polling, remote commands (wipe/restart/stop/start) |
| Audit logs | Shipped to Loki via fluent-bit |
| Fallback | Static config used if control plane unavailable |

Configuration: Set `CONTROL_PLANE_URL` and `CONTROL_PLANE_TOKEN` in `.env`

### Standalone Mode

No control plane required. Features:

| Feature | Source |
|---------|--------|
| Credentials | Static config (`STATIC_CREDENTIALS` or YAML) |
| Rate limits | Static config (`STATIC_RATE_LIMITS` or YAML) |
| Domain allowlist | Static file (`configs/coredns/allowlist.hosts`) |
| Domain aliases | Static config (`STATIC_DOMAIN_MAP` or YAML) |
| Agent management | Manual only (docker commands) |
| Audit logs | Local container logs only |

Configuration: Set `DATAPLANE_MODE=standalone` in `.env`

Use standalone mode for:
- Local development
- Air-gapped environments
- Single-agent deployments without central management

## Credential Injection

Agents can make direct HTTPS requests to allowed domains, but credentials won't be injected (the agent would need to know the API key). For automatic credential injection, use the `*.devbox.local` aliases:

```bash
# Inside agent container:

# Direct HTTPS (works, but no credential injection):
curl https://api.openai.com/v1/models  # Agent would need API key

# With credential injection (recommended):
curl http://openai.devbox.local/v1/models  # Credentials auto-injected by Envoy
```

How `*.devbox.local` aliases work:
1. Agent makes HTTP request to `openai.devbox.local`
2. CoreDNS resolves `*.devbox.local` to Envoy's IP
3. Envoy's Lua filter:
   - Maps `openai.devbox.local` → `api.openai.com`
   - Looks up credentials for `api.openai.com`
   - Injects Authorization header
   - Upgrades to HTTPS and forwards to real API
4. Agent never sees the actual credentials

## Docker Compose Profiles

```bash
# Base services (agent, envoy, dns-filter, agent-manager)
docker-compose up -d

# With audit logging (adds fluent-bit)
docker-compose --profile auditing up -d

# With SSH access via FRP tunnel
docker-compose --profile ssh up -d

# With both
docker-compose --profile auditing --profile ssh up -d
```

## Agent Image Variants

The agent container can be built with different toolsets:

| Variant | Contents | Size |
|---------|----------|------|
| `lean` | SSH, Python, Node.js, git, build tools, curl, jq | ~1.5GB |
| `dev` | Lean + Go, Rust, AWS CLI, Docker CLI | ~3GB |
| `ml` | Dev + PyTorch, numpy, pandas, scikit-learn, transformers | ~6GB |

Set in `.env`:
```bash
AGENT_VARIANT=lean  # or dev, ml
```

Build:
```bash
docker-compose build agent
```

## SSH Access via FRP

Agents can be accessed via SSH through FRP reverse tunnels. The data plane runs an FRP client (`frpc`) that connects outbound to the control plane's FRP server.

**Architecture:**
```
User SSH → Control Plane:6000 → frps → frpc → Agent:22
              (tunnel)                    (data plane)
```

**Setup:**

1. Configure in `.env`:
   ```bash
   # FRP connection to control plane
   FRP_SERVER_ADDR=control-plane-host
   FRP_AUTH_TOKEN=your-secure-token
   FRP_REMOTE_PORT=6000  # Unique per agent (6000, 6001, 6002...)

   # Your SSH public key
   SSH_AUTHORIZED_KEYS="ssh-rsa AAAA... user@host"
   ```

2. Start with SSH profile:
   ```bash
   docker-compose --profile ssh up -d
   ```

3. Connect from anywhere:
   ```bash
   ssh -p 6000 agent@control-plane-host
   ```

**Notes:**
- Each agent needs a unique `FRP_REMOTE_PORT` (control plane exposes 6000-6099)
- SSH uses key-based auth only (password disabled)
- FRP tunnel is outbound-only from data plane

## Services

| Service | Port | Network | Description |
|---------|------|---------|-------------|
| agent | 22 | agent-net | Isolated execution environment with SSH |
| envoy-proxy | 8443 | agent-net, infra-net | Egress proxy with credential injection |
| dns-filter | 53 | agent-net, infra-net | CoreDNS with domain allowlist |
| fluent-bit | 2020 | infra-net | Log aggregation, pushes to Loki (optional) |
| agent-manager | - | infra-net | Container lifecycle (polls CP, no inbound port) |
| frpc | - | agent-net, infra-net | FRP client for SSH tunnel (optional) |

## Agent Manager

The agent-manager polls the control plane every 30s (no inbound ports required):

1. Sends heartbeat with agent status (running, CPU, memory, uptime) using unique `AGENT_ID`
2. Receives any pending commands (wipe, restart, stop, start)
3. Executes command and reports result on next heartbeat

Each data plane instance must have a unique `AGENT_ID` configured.

**Control Plane API (called by agent-manager):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agent/heartbeat` | Send status, receive pending command |

**Control Plane API (called by admin UI):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/agents` | List all connected data planes |
| GET | `/api/v1/agents/{agent_id}/status` | Get agent status from last heartbeat |
| POST | `/api/v1/agents/{agent_id}/wipe` | Queue wipe command |
| POST | `/api/v1/agents/{agent_id}/restart` | Queue restart command |
| POST | `/api/v1/agents/{agent_id}/stop` | Queue stop command |
| POST | `/api/v1/agents/{agent_id}/start` | Queue start command |

## Cross-Machine Deployment

The control plane can manage multiple data planes running on different machines.

**Architecture (polling-based, outbound only from DP):**
```
Data Plane 1                            Control Plane
┌─────────────┐                        ┌─────────────┐
│   Envoy     │ ────── :8002 ───────►  │     API     │
│ fluent-bit  │ ────── :3100 ───────►  │    Loki     │
│agent-manager│ ────── :8002 ───────►  │  (manages)  │
└─────────────┘   (heartbeat/poll)     │   multiple  │
                                       │   agents    │
Data Plane 2                           │             │
┌─────────────┐                        │             │
│agent-manager│ ────── :8002 ───────►  │             │
└─────────────┘   (heartbeat/poll)     └─────────────┘
```

**On each data plane machine (.env):**
```bash
AGENT_ID=workstation-1                      # UNIQUE identifier for this data plane
CONTROL_PLANE_URL=http://192.168.1.50:8002  # Control plane IP
CONTROL_PLANE_TOKEN=your-token-here
LOKI_HOST=192.168.1.50                      # For fluent-bit (auditing)
```

Each data plane must have a unique `AGENT_ID` to be managed independently.

**Network requirements (outbound from data plane only):**

| From | To | Port | Purpose |
|------|-----|------|---------|
| Data plane (Envoy) | Control plane | 8002 | Credential/rate-limit lookups |
| Data plane (agent-manager) | Control plane | 8002 | Heartbeat polling |
| Data plane (fluent-bit) | Control plane | 3100 | Log shipping to Loki |

No inbound connections to data plane required.

## Security Controls

- **Network Isolation**: Agent on internal-only network, cannot reach internet directly
- **DNS Filtering**: Only allowlisted domains resolve
- **No Credential Exposure**: Agent never sees API keys
- **Rate Limiting**: Prevents runaway API usage
- **Audit Trail**: All egress requests logged
- **Read-only Filesystem**: Agent container has read-only root
- **Resource Limits**: CPU, memory, and PID limits on agent
- **No New Privileges**: Security hardening on agent container

## Testing

```bash
# Unit tests
pytest tests/ -v

# End-to-end tests (requires running data plane)
docker-compose up -d
pytest tests/test_e2e.py -v --run-e2e
```

## Troubleshooting

### Agent can't reach external services

1. Check DNS resolution: `docker exec agent nslookup api.openai.com`
2. Check domain is in allowlist: `cat configs/coredns/allowlist.hosts`
3. Check Envoy logs: `docker logs envoy-proxy`

### Credentials not being injected

1. Verify using `*.devbox.local` URL (not direct HTTPS)
2. Check domain mapping exists: `echo $STATIC_DOMAIN_MAP`
3. Check credentials configured: `echo $STATIC_CREDENTIALS | tr '|' '\n'`
4. Check Envoy logs for injection messages

### Control plane connection failing

1. Check token is set: `echo $CONTROL_PLANE_TOKEN`
2. Check control plane is reachable from infra-net
3. Data plane will fall back to static config after 30s backoff

## Files

```
data-plane/
├── docker-compose.yml          # Docker Compose configuration
├── agent.Dockerfile            # Agent container image (lean/dev/ml variants)
├── agent-entrypoint.sh         # Agent startup script (SSH setup)
├── .env.example                # Environment template
├── configs/
│   ├── static-config.yaml      # YAML configuration for standalone mode
│   ├── envoy/
│   │   └── envoy-enhanced.yaml # Envoy proxy configuration
│   ├── coredns/
│   │   ├── Corefile            # CoreDNS configuration
│   │   └── allowlist.hosts     # Allowed domains
│   ├── fluent-bit/
│   │   ├── fluent-bit.conf     # Log forwarding config
│   │   └── parsers.conf        # Log parsers
│   └── frpc/
│       └── frpc.toml           # FRP client configuration
├── services/
│   └── agent-manager/
│       ├── main.py             # FastAPI service
│       └── Dockerfile
├── scripts/
│   └── load-static-config.sh   # YAML to env var converter
└── tests/
    ├── test_credential_injector.py  # Unit tests
    └── test_e2e.py                  # Integration tests
```
