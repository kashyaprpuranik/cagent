# Configuration Guide

This guide covers configuring domain policies, agent management, and per-agent settings.

## Configuration Methods

| Mode | Method | Description |
|------|--------|-------------|
| **Standalone** | Local Admin UI | http://localhost:8080 - structured form editor |
| **Standalone** | cagent.yaml | Edit `configs/cagent.yaml` directly |
| **Connected** | Control Plane UI | http://localhost:9080 - full admin console |
| **Connected** | Control Plane API | REST API endpoints |

## Standalone Mode: cagent.yaml

In standalone mode, all configuration is in a single YAML file:

```yaml
# configs/cagent.yaml
mode: standalone

dns:
  upstream: [8.8.8.8, 8.8.4.4]
  cache_ttl: 300

rate_limits:
  default:
    requests_per_minute: 120
    burst_size: 20

domains:
  - domain: api.openai.com
    alias: openai              # Creates openai.devbox.local
    timeout: 120s
    rate_limit:
      requests_per_minute: 60
      burst_size: 10
    credential:
      header: Authorization
      format: "Bearer {value}"
      env: OPENAI_API_KEY      # Read from environment

  - domain: pypi.org
    read_only: true            # Block POST/PUT/DELETE
```

The Admin UI at http://localhost:8081 provides a structured editor:
- **Domains tab**: Add/edit/delete with validation
- **Settings tab**: DNS, rate limits, mode
- **Raw YAML tab**: Direct editing

## Connected Mode

For connected mode (centralized management via control plane), see the [cagent-control](https://github.com/kashyaprpuranik/cagent-control) repo.

## Domain Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Domain pattern (e.g., `api.openai.com`, `*.github.com`) |
| `alias` | string | Creates `{alias}.devbox.local` shortcut |
| `description` | string | Human-readable description |
| `allowed_paths` | list | Path patterns to allow (default: all) |
| `requests_per_minute` | int | Rate limit (requests per minute) |
| `burst_size` | int | Rate limit burst allowance |
| `credential` | object | Credential to inject (`header`, `format`, `value`) |
| `cell_id` | string | Scope to specific cell (null = tenant-global) |

### Path Filtering

By default, all paths are allowed for a domain. You can restrict access to specific paths using the `allowed_paths` field.

**Pattern syntax:**
- `/v1/chat/completions` - exact match
- `/v1/chat/*` - prefix match (matches `/v1/chat/completions`, `/v1/chat/stream`)
- `/api/v2*` - prefix match without slash (matches `/api/v2/users`, `/api/v2`)

**Use cases:**
- Block file upload endpoints (exfiltration risk)
- Restrict to read-only API operations
- Allow specific API versions only

### Credential Injection

Credentials are stored on domain policies and injected by Envoy at the proxy layer. The cell never sees API keys.

With the MITM proxy enabled (default in `local.sh`), credential injection works for both HTTP and HTTPS requests. The cell can use `curl https://api.openai.com/v1/models` directly and credentials are injected transparently.

**Domain aliases**: Setting `alias: "openai"` also creates an `openai.devbox.local` shortcut as an alternative. The cell can use either:
- `curl https://api.openai.com/v1/models` (HTTPS via MITM proxy)
- `curl http://openai.devbox.local/v1/models` (HTTP alias)

```bash
# In cagent.yaml:
# - domain: api.openai.com
#   alias: openai
#   credential:
#     header: Authorization
#     format: "Bearer {value}"
#     env: OPENAI_API_KEY
#
# Cell can use:
#   curl https://api.openai.com/v1/models   (HTTPS, via MITM proxy)
#   curl http://openai.devbox.local/v1/models (HTTP alias)
```

## HTTPS Support (MITM Proxy)

By default, `local.sh` starts a MITM proxy (`mitmproxy`) that enables full HTTPS egress support. This allows all Envoy security controls (domain allowlist, rate limiting, credential injection, path filtering) to work for HTTPS requests.

### How it works

```
Cell ──HTTPS──> mitmproxy:8080 (TLS termination) ──HTTP──> Envoy:8443 (security controls) ──> upstream
Cell ──HTTP───> Envoy:8443 (direct, no extra hop) ──> upstream
```

1. The cell's `HTTPS_PROXY` points to mitmproxy (`10.200.1.15:8080`)
2. mitmproxy terminates TLS using a locally-generated CA certificate
3. The decrypted HTTP request is forwarded to Envoy, where all security controls apply
4. Envoy forwards the request to the upstream server over HTTPS

The MITM CA certificate is automatically trusted by the cell container (combined into the system CA bundle at startup).

### Limitations

- **Certificate pinning**: Applications that pin specific certificates will fail through the MITM proxy (inherent limitation of TLS interception)
- **Latency**: HTTPS requests have ~1-2ms additional latency from the extra network hop

## SSH Access

Cell containers run an SSH server (key-auth only, no passwords, no root login). SSH is exposed on host port 2222 by default.

### Quick Start

```bash
# Set your public key and start the cell
SSH_AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" docker compose --profile dev up -d

# Connect
ssh -p 2222 cell@localhost
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_AUTHORIZED_KEYS` | (empty) | Public key(s) to authorize, newline-separated |
| `SSH_PORT` | `2222` | Host port mapped to container SSH (port 22) |

You can also mount a keys file instead of (or in addition to) the environment variable:

```yaml
# In docker-compose.yml, uncomment:
volumes:
  - ./ssh-keys/authorized_keys:/ssh-keys/authorized_keys:ro
```

### Persistent Sessions (tmux)

SSH sessions auto-attach to a tmux session. Work persists across SSH disconnects and container restarts (the tmux socket is stored on the persistent `/workspace` volume).

```bash
# List sessions
ssh -p 2222 cell@localhost session list

# Detach from tmux: Ctrl+B, then D
# Reconnect: ssh again — auto-attaches to existing session
```

### Multiple Cells

When scaling cells (`--scale cell-dev=N`), each container needs a unique host port. Use a port range:

```bash
# In .env or shell
SSH_PORT=2222-2232

# Find which port maps to which container
docker compose port --index 1 cell-dev 22
docker compose port --index 2 cell-dev 22
```

## Data Loss Prevention (DLP)

The MITM proxy scans outbound request bodies for leaked secrets and PII before they leave the data plane. Configured via `configs/mitm/dlp_config.json` (standalone) or pushed from the control plane (connected mode).

### Configuration

```json
{
  "enabled": true,
  "mode": "log",
  "skip_domains": ["api.openai.com"],
  "custom_patterns": [
    {"name": "aws_access_key", "regex": "AKIA[0-9A-Z]{16}"},
    {"name": "email_bulk", "regex": "[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+", "threshold": 5}
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable/disable DLP scanning |
| `mode` | string | `log` (warn only), `block` (return 403), or `redact` (replace matches with `[REDACTED]`) |
| `skip_domains` | list | Domains to skip scanning (e.g., AI API providers where tokens are expected) |
| `custom_patterns` | list | Detection patterns (see below) |

### Patterns

All detection patterns are defined in `custom_patterns`. Each pattern has:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Pattern identifier (used in violation logs) |
| `regex` | string | Yes | Regular expression (google-re2 syntax) |
| `threshold` | int | No | Minimum match count to trigger (for bulk detection) |

Without `threshold`, any single match triggers a violation. With `threshold`, the pattern only fires when the match count reaches the threshold — useful for detecting bulk data extraction (e.g., 5+ email addresses in one request body is suspicious, but a single email is normal).

### Default Patterns

In standalone mode, warden writes a default config with 12 built-in patterns:

| Pattern | Type | Description |
|---------|------|-------------|
| `aws_access_key` | Secret | AWS access key IDs (`AKIA...`) |
| `github_token` | Secret | GitHub personal/OAuth/app tokens |
| `openai_api_key` | Secret | OpenAI API keys (`sk-...`) |
| `anthropic_api_key` | Secret | Anthropic API keys (`sk-ant-...`) |
| `private_key` | Secret | PEM-encoded private keys |
| `jwt` | Secret | JSON Web Tokens |
| `generic_api_key` | Secret | Common `api_key=...` / `secret_key=...` patterns |
| `connection_string` | Secret | Database/message broker connection URIs |
| `ssn` | PII | US Social Security Numbers |
| `credit_card` | PII | 16-digit card numbers |
| `email_bulk` | PII | 5+ email addresses in one request (threshold-based) |
| `phone_bulk` | PII | 5+ US phone numbers in one request (threshold-based) |

To disable a specific pattern, remove it from `custom_patterns`. To add a new pattern, append it to the list.

### Connected Mode

In connected mode, the control plane pushes DLP config via `GET /api/v1/dlp-policies`. The CP config fully replaces the local defaults — warden writes the received config to `dlp_config.json` and restarts the MITM proxy.

### Violations

Violations are logged as structured JSON to stdout. Vector picks them up via Docker log collection and ships them to the configured sinks (OpenObserve, file, S3, etc.). In connected mode, violations are visible in the control plane log viewer.

## Log Collection

Enabled with `--profile auditing`. Vector collects logs from all containers (cell, HTTP proxy, DNS filter, warden) and ships them to:

| Sink | Standalone | Connected | Notes |
|------|-----------|-----------|-------|
| **OpenObserve** (local log store) | Yes | Yes | Per-DP log analytics, queryable by warden for the traffic dashboard |
| **Local files** | Yes | Yes (backup) | `/var/log/vector/backup/%Y-%m-%d.log` |
| **S3** | Optional | — | Uncomment in `configs/vector/sinks/standalone.yaml` |
| **Elasticsearch** | Optional | — | Uncomment in `configs/vector/sinks/standalone.yaml` |

**OpenObserve** runs as the `log-store` container on `infra-net` (not exposed externally). Warden queries it for the admin UI analytics dashboard (top blocked domains, bandwidth, error rates). Default retention is 30 days (`LOG_RETENTION_DAYS` env var).

In connected mode, the control plane queries logs by proxying requests through warden (via mTLS).
