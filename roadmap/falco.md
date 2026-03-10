# Falco Adoption Plan

Runtime syscall monitoring for cell containers, especially critical for permissive security profiles.

## Motivation

Today's security stack (seccomp + gVisor) is prevention-only with no visibility. When users choose permissive mode, most prevention is relaxed — there's no safety net. Falco adds real-time detection and alerting at the syscall level: what is the agent actually doing?

## Security Tier Model

| Tier | Prevention | Visibility |
|------|-----------|------------|
| Restrictive | gVisor + strict seccomp | Falco optional (not much gets through) |
| Standard | Default seccomp | Falco recommended |
| Permissive | Minimal seccomp | Falco essential — only safety net |

## Architecture

```
    Cell container
        │
        │ syscalls
        ▼
    Kernel (eBPF) ◄──── Falco (host-level, reads syscall stream)
                              │
                              │ alerts (JSON)
                              ▼
                         Vector ──► CP API (audit trail)
                                        │
                                        ▼
                                   Warden (kill command)
```

Falco runs on the host, not inside the cell. It uses the eBPF driver to tap the kernel's syscall stream — no kernel module needed on modern kernels (5.8+). It filters events by container ID so it only watches cell containers.

## What Falco Detects

For permissive-mode cells specifically:

| Threat | Falco Rule |
|--------|-----------|
| Reverse shell | Outbound shell process with network socket |
| Binary download + execute | Write to /tmp or /workspace then execve |
| Crypto mining | Unexpected long-running CPU-bound process |
| Credential theft | Read from /proc/*/environ, /etc/shadow, mounted secrets |
| Container escape | Mount namespace manipulation, ptrace, /proc/sysrq-trigger |
| Privilege escalation | setuid/setgid calls, capability changes |
| Unexpected network | Raw socket creation, DNS over non-standard port |

## Falco Deployment

- Runs as a container on the host with `--privileged` (needs eBPF access)
- eBPF driver (not kernel module) — works on Ubuntu 22.04+ / kernel 5.8+
- ~50-70MB memory, minimal CPU unless alert volume is high
- Outputs JSON alerts to stdout → Vector picks them up
- Custom rules mounted from `configs/falco/`

### docker-compose addition

```yaml
falco:
  image: falcosecurity/falco:latest
  privileged: true
  volumes:
    - /var/run/docker.sock:/host/var/run/docker.sock:ro
    - /proc:/host/proc:ro
    - /dev:/host/dev:ro
    - ./configs/falco/falco_rules.yaml:/etc/falco/falco_rules.local.yaml:ro
  networks:
    - infra-net
  profiles:
    - auditing
```

Runs under the `auditing` profile — same as Vector log shipping. Permissive-mode tenants would have this enabled by default.

## Alert Pipeline

1. Falco detects syscall pattern matching a rule
2. Falco emits JSON alert to stdout
3. Vector collects from Falco container logs (existing Docker log source)
4. Vector transforms: enrich with tenant_id, cell_id, severity
5. Vector ships to CP API (existing connected-mode sink)
6. CP stores in audit_trail table
7. CP optionally triggers automated response (kill cell, notify user)

### Alert format (Falco JSON output)

```json
{
  "time": "2026-03-04T12:00:00Z",
  "rule": "Reverse Shell Detected",
  "priority": "Critical",
  "output": "Reverse shell connection from cell container (user=cell command=bash -i >& /dev/tcp/...)",
  "output_fields": {
    "container.id": "abc123",
    "container.name": "cell",
    "proc.name": "bash",
    "fd.sip": "10.0.0.1"
  }
}
```

## Custom Rules

```yaml
# configs/falco/falco_rules.yaml

# Detect binary download + execute in cell
- rule: Cell Binary Execution
  desc: A binary was downloaded and executed inside a cell container
  condition: >
    spawned_process and container.name = "cell"
    and proc.exe startswith /tmp/
  output: "Binary executed from /tmp in cell (command=%proc.cmdline)"
  priority: WARNING

# Detect credential file access
- rule: Cell Credential Access
  desc: Cell process reading sensitive files
  condition: >
    open_read and container.name = "cell"
    and (fd.name startswith /etc/shadow or fd.name startswith /proc/*/environ)
  output: "Credential file access in cell (file=%fd.name command=%proc.cmdline)"
  priority: CRITICAL

# Detect reverse shell
- rule: Cell Reverse Shell
  desc: Shell with network redirect in cell
  condition: >
    spawned_process and container.name = "cell"
    and proc.name in (bash, sh, zsh)
    and fd.type = ipv4
  output: "Possible reverse shell in cell (command=%proc.cmdline connection=%fd.name)"
  priority: CRITICAL
```

Rules would be parameterized per security profile:
- **Restrictive**: Minimal rules (gVisor handles most threats)
- **Standard**: Medium ruleset (common threats)
- **Permissive**: Full ruleset (everything above + more)

## Automated Response

### Phase 1: Alert only
Falco alerts → Vector → CP audit trail. Customer sees alerts in dashboard.

### Phase 2: Kill on critical
CP receives critical alert → sends `kill` command to warden → warden stops cell container.

```
Falco (critical alert) → Vector → CP → pending_command = "stop" → Warden → docker stop cell
```

This uses the existing pending_command infrastructure in cell_state.

### Phase 3: Configurable thresholds
Per-tenant configuration:
- Which alert severities trigger auto-kill
- Cool-down period before killing (avoid false positives)
- Notification preferences (email, webhook)

## CP Changes

### Database

```sql
-- New table or extend audit_trail
ALTER TABLE audit_trail ADD COLUMN severity TEXT;
ALTER TABLE audit_trail ADD COLUMN falco_rule TEXT;
```

### API

- `GET /api/v1/tenants/{id}/security-alerts` — list Falco alerts for a tenant
- Alert ingestion endpoint for Vector (or reuse existing audit trail endpoint)

### Frontend

- Security alerts panel in tenant dashboard
- Alert severity badges on cell status cards
- Configuration UI for automated response thresholds (Phase 3)

## Migration Phases

### Phase 1: Falco sidecar + default rules (1 week)

- Add Falco container to docker-compose.yml under `auditing` profile
- Write base ruleset for cell container monitoring
- Vector picks up Falco logs, ships to CP
- CP stores in audit trail
- No automated response — alert only
- Test: trigger known-bad syscalls in cell, verify alerts arrive at CP

### Phase 2: Profile-aware rules (3-4 days)

- Different rulesets per security profile (restrictive/standard/permissive)
- Warden selects ruleset based on cell's runtime_policy
- Provisioner enables Falco by default for permissive-mode tenants
- Test: permissive cell triggers full ruleset, restrictive cell triggers minimal

### Phase 3: Automated kill (3-4 days)

- CP receives critical alert → issues stop command via pending_command
- Cool-down logic: don't kill the same cell twice in N minutes
- Customer notification (audit trail entry + optional webhook)
- Test: reverse shell in permissive cell → auto-terminated within 30s

### Phase 4: Customer-facing dashboard (1 week)

- Security alerts page in frontend
- Per-tenant alert configuration
- Historical alert analytics
- Export/webhook integration

## What Gets Added

- `configs/falco/` directory (rule files per security profile)
- Falco service in docker-compose.yml (under `auditing` profile)
- Vector transform for Falco alert enrichment
- CP alert ingestion + storage
- Frontend security alerts panel

## What Stays the Same

- Seccomp profiles (prevention layer, unchanged)
- gVisor (restrictive mode, unchanged)
- Existing audit_trail infrastructure (extended, not replaced)
- Warden pending_command flow (reused for kill)

## Risks

| Risk | Mitigation |
|------|------------|
| Privileged container requirement | Falco needs eBPF access; isolate on infra-net, read-only mounts |
| False positives triggering auto-kill | Phase 1 is alert-only; auto-kill has cool-down; customer configurable |
| Performance overhead on high-syscall workloads | eBPF is low-overhead; tune rules to avoid noisy patterns |
| gVisor compatibility | Falco eBPF may not see syscalls intercepted by gVisor — only relevant for restrictive mode where Falco is optional anyway |
| Rule maintenance | Start with Falco's upstream ruleset, customize minimally |

## gVisor Interaction

Important caveat: when gVisor is active (restrictive mode), Falco's eBPF driver may not see all syscalls because gVisor intercepts them in userspace before they reach the kernel. This is fine because:
- Restrictive mode already has strong prevention (gVisor + strict seccomp)
- Falco is optional/minimal for restrictive mode
- Falco is essential for permissive mode where gVisor is disabled

## Effort Estimate

- Phase 1: 1 week (Falco sidecar + rules + Vector pipeline)
- Phase 2: 3-4 days (profile-aware rules)
- Phase 3: 3-4 days (automated response)
- Phase 4: 1 week (dashboard)
- Total: ~3-4 weeks across all phases

Can be parallelized with OPA adoption — they touch different parts of the stack.
