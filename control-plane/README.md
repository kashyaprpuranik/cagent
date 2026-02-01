# AI Devbox - Control Plane

The control plane provides centralized management, policy enforcement, secrets storage, and observability for the AI Devbox platform.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Control Plane                              │
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────┐        │
│  │  Admin UI   │───►│ Control Plane│───►│  PostgreSQL │        │
│  │  (React)    │    │     API      │    │  (state)    │        │
│  └─────────────┘    └──────────────┘    └─────────────┘        │
│        │                   │                                    │
│        │                   │ (read logs)                        │
│        │                   ▼                                    │
│        │            ┌─────────────┐    ┌─────────────┐         │
│        └───────────►│   Grafana   │───►│    Loki     │         │
│                     │ (dashboards)│    │   (logs)    │         │
│                     └─────────────┘    └─────────────┘         │
│                                              ▲                  │
└──────────────────────────────────────────────│──────────────────┘
                                               │ (write logs)
        ┌──────────────────────────────────────┼──────────────┐
        │                                      │              │
┌───────┴──────┐  ┌───────────────┐  ┌───────────────┐
│ Data Plane 1 │  │ Data Plane 2  │  │ Data Plane N  │
│ (fluent-bit) │  │ (fluent-bit)  │  │ (fluent-bit)  │
│ (agent-mgr)  │  │ (agent-mgr)   │  │ (agent-mgr)   │
└──────────────┘  └───────────────┘  └───────────────┘
      │                  │                   │
      └──────── heartbeat/poll (outbound) ───┘
```

**Log Flow**:
- **Write**: Data plane fluent-bit → Loki (direct, port 3100)
- **Read**: Admin UI → Control Plane API → Loki (proxied queries)

**Multi-Data Plane Management**:
- Each data plane has a unique `agent_id`
- Admin UI shows data plane selector to switch between managed instances
- All commands (start/stop/restart/wipe) are per-agent

**Multi-Tenancy**:
- Tenants are organizational units that group agents
- Each agent belongs to exactly one tenant
- Configuration (secrets, allowlist, rate limits) can be:
  - **Tenant-global**: Uses special `__default__` agent ID, applies to all agents in tenant
  - **Agent-specific**: Scoped to a single agent, takes precedence over tenant-global
- Token scoping:
  - **Super admin**: Access to all tenants (platform operators)
  - **Admin**: Scoped to a single tenant
  - **Agent**: Scoped to a single agent within a tenant

## Services

| Service | Port | Description |
|---------|------|-------------|
| control-plane-api | 8002 | FastAPI REST API |
| admin-ui | 9080 | React admin console |
| grafana | 3000 | Dashboards and log viewer |
| loki | 3100 | Log storage (receives from data plane) |
| postgres | 5432 | State storage (internal) |
| frps | 7000, 6000-6099 | FRP server for agent SSH tunnels |

## SSH Access to Agents

Agents can be accessed via SSH through FRP reverse tunnels. The control plane runs an FRP server (`frps`) that accepts connections from data plane FRP clients (`frpc`).

**Architecture:**
```
User SSH → Control Plane:6000 → frps → frpc → Agent:22
              (tunnel)                    (data plane)
```

**Setup:**

1. Configure FRP token in control plane `.env`:
   ```bash
   FRP_AUTH_TOKEN=your-secure-token
   ```

2. Configure data plane `.env`:
   ```bash
   FRP_SERVER_ADDR=control-plane-host
   FRP_AUTH_TOKEN=your-secure-token
   FRP_REMOTE_PORT=6000  # Unique per agent
   SSH_AUTHORIZED_KEYS="ssh-rsa AAAA... user@host"
   ```

3. Start data plane with SSH profile:
   ```bash
   docker-compose --profile ssh up -d
   ```

4. Connect:
   ```bash
   ssh -p 6000 agent@control-plane-host
   ```

**FRP Dashboard:** http://localhost:7500 (admin / `FRP_DASHBOARD_PASSWORD`)

## Quick Start

```bash
# Generate encryption key for secrets
export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Start control plane
docker-compose up -d

# Access services:
# - Admin UI: http://localhost:9080
# - API Docs: http://localhost:8002/docs
# - Grafana:  http://localhost:3000 (admin/admin)
```

## API Documentation

The control plane API is built with FastAPI and auto-generates OpenAPI documentation:

- **Swagger UI**: http://localhost:8002/docs
- **ReDoc**: http://localhost:8002/redoc
- **OpenAPI JSON**: http://localhost:8002/openapi.json

## API Endpoints

### Health & Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/info` | System information |

### Secrets Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/secrets` | List all secrets (metadata only) |
| POST | `/api/v1/secrets` | Create a new secret |
| POST | `/api/v1/secrets/{name}/rotate` | Rotate a secret |
| DELETE | `/api/v1/secrets/{name}` | Delete a secret |
| GET | `/api/v1/secrets/{name}/value` | Get decrypted secret value |
| GET | `/api/v1/secrets/for-domain` | Lookup secret by domain or alias (for Envoy) |

Domain aliases (e.g., `openai.devbox.local` → `api.openai.com`) are configured via the `alias` field on secrets. See [Data Models](#data-models) below.

### Rate Limits

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/rate-limits` | List all rate limits |
| POST | `/api/v1/rate-limits` | Create rate limit |
| PUT | `/api/v1/rate-limits/{id}` | Update rate limit |
| DELETE | `/api/v1/rate-limits/{id}` | Delete rate limit |
| GET | `/api/v1/rate-limits/for-domain` | Lookup rate limit by domain (for Envoy) |

### Allowlist

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/allowlist` | List allowlist entries |
| POST | `/api/v1/allowlist` | Add allowlist entry |
| DELETE | `/api/v1/allowlist/{id}` | Remove allowlist entry |
| GET | `/api/v1/allowlist/export` | Export allowlist (CoreDNS format) |

### Audit Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/audit-logs` | Query audit logs |
| POST | `/api/v1/audit-logs` | Create audit log entry |

### Multi-Data Plane Management (Polling-based)

The control plane can manage multiple data planes. Each data plane has an agent-manager that polls the control plane for commands.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/agents` | List all connected data planes |
| POST | `/api/v1/agent/heartbeat` | Receive heartbeat from agent-manager, return pending command |
| GET | `/api/v1/agents/{agent_id}/status` | Get agent status from last heartbeat |
| POST | `/api/v1/agents/{agent_id}/wipe` | Queue wipe command (picked up on next heartbeat) |
| POST | `/api/v1/agents/{agent_id}/restart` | Queue restart command |
| POST | `/api/v1/agents/{agent_id}/stop` | Queue stop command |
| POST | `/api/v1/agents/{agent_id}/start` | Queue start command |

All connections are outbound from data plane - no inbound ports needed on data plane.

### API Token Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tokens` | List all API tokens (admin only) |
| POST | `/api/v1/tokens` | Create new token (admin only) |
| DELETE | `/api/v1/tokens/{id}` | Delete token (admin only) |
| PATCH | `/api/v1/tokens/{id}` | Enable/disable token (admin only) |

### Tenant Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tenants` | List all tenants (super admin only) |
| POST | `/api/v1/tenants` | Create new tenant (super admin only) |
| DELETE | `/api/v1/tenants/{id}` | Delete tenant (super admin only) |

### Agent Approval

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agents/{agent_id}/approve` | Approve agent (admin only) |
| POST | `/api/v1/agents/{agent_id}/reject` | Reject and remove agent (admin only) |
| POST | `/api/v1/agents/{agent_id}/revoke` | Revoke agent approval (admin only) |

## Authentication

All API endpoints (except `/health` and `/api/v1/info`) require Bearer token authentication:

```bash
curl -H "Authorization: Bearer your-token" http://localhost:8002/api/v1/secrets
```

### Token Types

| Type | Purpose | Access |
|------|---------|--------|
| `admin` (super) | Platform management | Full API access across all tenants |
| `admin` | Tenant management | Full API access within assigned tenant |
| `agent` | Data plane | Heartbeat, secrets/for-domain, rate-limits/for-domain (scoped to agent_id) |

### Token Sources

1. **Database tokens** (recommended): Created via API or Admin UI
2. **Legacy tokens** (dev only): `API_TOKENS` environment variable (treated as admin tokens)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `ENCRYPTION_KEY` | - | Fernet key for secret encryption |
| `API_TOKENS` | `dev-token` | Comma-separated allowed API tokens |
| `LOKI_URL` | `http://loki:3100` | Loki URL for log queries |
| `DEFAULT_RATE_LIMIT_RPM` | `120` | Default requests per minute for unlisted domains |
| `DEFAULT_RATE_LIMIT_BURST` | `20` | Default burst size for unlisted domains |

## Cross-Machine Deployment

The control plane manages multiple data planes, which can run on different machines.

**Architecture (polling-based):**
```
Data Plane 1                            Control Plane
┌─────────────┐                        ┌─────────────┐
│   Envoy     │ ────── :8002 ───────►  │     API     │
│ fluent-bit  │ ────── :3100 ───────►  │    Loki     │
│agent-manager│ ────── :8002 ───────►  │  (manages)  │
└─────────────┘   (heartbeat/poll)     │             │
                                       │  Multiple   │
Data Plane 2                           │   Agents    │
┌─────────────┐                        │             │
│   Envoy     │ ────── :8002 ───────►  │             │
│ fluent-bit  │ ────── :3100 ───────►  │             │
│agent-manager│ ────── :8002 ───────►  │             │
└─────────────┘   (heartbeat/poll)     └─────────────┘
```

All connections are outbound from data planes - no inbound ports needed on data planes.

**Network requirements (control plane perspective):**

| From | To | Port | Purpose |
|------|-----|------|---------|
| Data plane (Envoy) | Control plane | 8002 | Credential/rate-limit lookups |
| Data plane (agent-manager) | Control plane | 8002 | Heartbeat polling |
| Data plane (fluent-bit) | Control plane | 3100 | Log shipping to Loki |

**Data plane configuration:**
Each data plane needs a unique `AGENT_ID` in its `.env` file:
```bash
AGENT_ID=workstation-1  # Unique identifier for this data plane
CONTROL_PLANE_URL=http://control-plane-host:8002
CONTROL_PLANE_TOKEN=your-token  # Agent token scoped to this agent_id
```

**Tenant-global configuration:**
Each tenant has a virtual `__default__` agent that holds tenant-wide defaults. Configuration attached to `__default__` applies to all agents in the tenant unless overridden by agent-specific config.

## Data Models

### Tenant

```json
{
  "id": 1,
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "created_at": "2024-01-15T10:30:00Z",
  "agent_count": 5
}
```

Tenants are organizational units. Each tenant automatically gets a `__default__` agent for tenant-global configuration.

### Secret

```json
{
  "name": "openai-api-key",
  "domain_pattern": "api.openai.com",
  "alias": "openai",
  "header_name": "Authorization",
  "header_format": "Bearer {value}",
  "rotation_days": 90,
  "agent_id": null
}
```

The `alias` field creates a `*.devbox.local` mapping:
- `alias: "openai"` → Agent uses `http://openai.devbox.local/...`
- Envoy maps to `api.openai.com` and injects credentials

The `agent_id` field scopes the secret:
- `null` or `"__default__"`: Tenant-global (applies to all agents)
- `"agent-id"`: Agent-specific (overrides tenant-global for that agent)

### Rate Limit

```json
{
  "domain_pattern": "api.openai.com",
  "requests_per_minute": 60,
  "burst_size": 10,
  "enabled": true,
  "agent_id": null
}
```

### Allowlist Entry

```json
{
  "entry_type": "domain",
  "value": "api.openai.com",
  "description": "OpenAI API",
  "enabled": true,
  "agent_id": null
}
```

Entry types: `domain`, `ip`, `command`

All configuration models support `agent_id` for scoping (null = tenant-global, specific ID = agent-only).

## Development

```bash
# Run locally (requires PostgreSQL)
cd services/control-plane
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Run tests
pytest tests/ -v
```

## Database Seeding

The database is automatically seeded on first startup (when no agents exist). You can also seed manually:

```bash
cd services/control-plane

# Seed with defaults
python seed.py

# Reset and reseed
python seed.py --reset

# Show generated tokens
python seed.py --show-token
```

Default seed data includes:
- Default tenant with slug `default`
- `__default__` agent for tenant-global config
- Super admin token `default-admin`
- Test agents (`test-agent`, `pending-agent`)
- Sample allowlist entries, rate limits, and secrets

## Files

```
control-plane/
├── docker-compose.yml          # Service orchestration
├── services/
│   ├── control-plane/
│   │   ├── main.py             # FastAPI application
│   │   ├── seed.py             # Database seeder
│   │   ├── entrypoint.sh       # Docker entrypoint (auto-seeds)
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   └── admin-ui/
│       ├── src/                # React application
│       ├── package.json
│       └── Dockerfile
└── configs/
    └── grafana/
        └── provisioning/       # Grafana datasources & dashboards
```
