# Distributed Tracing Plan

OpenTelemetry-based request tracing across control plane and data plane.

## Motivation

Debugging cross-service issues today requires manually grepping logs across multiple containers with no request correlation. A single user action (e.g. "provision a cell") touches CP API → CP background task → ARQ job → Hetzner API → warden heartbeat → config generation — but there's no thread connecting these steps. When something fails mid-chain, finding the root cause means opening 4+ log streams and matching timestamps by eye.

Distributed tracing solves this by assigning a single trace ID to each request and propagating it across service boundaries. Every span (unit of work) links back to the trace, giving a full timeline of what happened, where it stalled, and what failed.

### Goals

1. **Request correlation**: link all log lines for a single request across services
2. **End-to-end observability**: see the full lifecycle of operations like cell provisioning, config sync, credential injection
3. **CP↔DP correlation**: trace a CP API call through to the warden action it triggers
4. **Debugging aid**: pinpoint latency bottlenecks and failure points without manual log correlation

## Architecture

```
                         ┌──────────────────────────────────────┐
                         │           Control Plane               │
                         │                                      │
  User ──► CP API ──────►│  FastAPI ──► background tasks ──► ARQ │
           (traceparent) │    │              │                   │
                         │    │  trace_id    │  trace_id in      │
                         │    │  in logs     │  job metadata     │
                         └────┼──────────────┼──────────────────┘
                              │
                              │   OTel SDK exports spans
                              ▼
                         ┌──────────────────┐
                         │  Jaeger (CP-only) │
                         │  OTLP/gRPC :4317  │
                         │  UI on :16686     │
                         └──────────────────┘


                         ┌──────────────────────────────────────┐
                         │           Data Plane                  │
                         │                                      │
  Envoy ──► ext_authz ──►│  Warden FastAPI    config_generator  │
  (x-request-id)         │    │                                 │
                         │    │  trace_id in logs               │
                         │    │                                 │
                         │    │  OTel SDK exports spans          │
                         │    ▼                                 │
                         │  OpenObserve (log-store, already     │
                         │  running under auditing profile)     │
                         │  OTLP/HTTP :5080  ·  traces + logs   │
                         └──────────────────────────────────────┘
```

Each plane stores traces locally. The CP exports spans to Jaeger. The DP exports spans to the existing OpenObserve instance (`log-store` container, already running under the `auditing` profile) — no new infrastructure needed on the DP side.

Trace context propagation uses the W3C `traceparent` header standard. When CP calls DP (via `proxy_to_warden()`), the traceparent header is forwarded so the DP can log the same trace ID — but spans stay local to each plane. Envoy generates `x-request-id` for access log correlation.

## Current State

| Component | What exists | Gap |
|-----------|------------|-----|
| Envoy access log | JSON format with authority, path, response_code, credential_injected | No `x-request-id` field; no request ID generation enabled |
| Vector log pipeline | Parses Envoy logs, expects `.request_id` field (vector.yaml line 83) | Field is always empty — Envoy doesn't generate it |
| CP auth middleware | Structured logs: `req %s %s \| ip=%s tenant=%s cell=%s token=%s(%s)` | No request/trace ID |
| CP → DP calls | `proxy_to_warden()` in `warden_proxy.py` uses httpx | No traceparent propagation |
| Warden middleware | CORS only | No tracing middleware |
| CP middleware | SecurityHeaders, CloudflareOrigin, CORS | No tracing middleware |
| OpenObserve (DP) | Running as `log-store` under `auditing` profile; receives logs from Vector | Supports OTLP trace ingestion natively — not yet configured for traces |
| OTel packages | None in either repo | Everything needs to be added |

## What Gets Added

### Python packages (both repos)

```
opentelemetry-api
opentelemetry-sdk
opentelemetry-instrumentation-fastapi
opentelemetry-instrumentation-httpx
opentelemetry-exporter-otlp-proto-grpc
```

### CP-specific

- `tracing.py` module: OTel SDK init, Jaeger exporter config, helper to inject trace_id into structured logs
- FastAPI auto-instrumentation (all routes get spans automatically)
- httpx auto-instrumentation (`proxy_to_warden()` propagates `traceparent` to DP)
- ARQ job trace propagation: `trace_id` stored in job metadata, linked as child span in worker
- Background task trace propagation: capture span context before `asyncio.create_task`, restore in task
- Jaeger all-in-one container in CP docker-compose (dev) or standalone (staging/prod)

### DP-specific

- `tracing.py` module: OTel SDK init, exports spans to local OpenObserve via OTLP/HTTP
- FastAPI auto-instrumentation on warden
- Envoy config changes: enable `x-request-id` generation, add to access log JSON format
- Vector: `request_id` field already parsed — starts working once Envoy generates it
- No new containers — OpenObserve (`log-store`) already runs under the `auditing` profile and accepts OTLP traces natively

## What Stays the Same

- Existing log formats (trace_id is appended, not replacing existing fields)
- Vector pipeline (already handles request_id; just starts receiving real values)
- Envoy proxy behavior (x-request-id is metadata, doesn't affect routing)
- Warden polling loop (gets spans but behavior unchanged)

## Integration Details

### Envoy: x-request-id

Envoy has built-in `x-request-id` generation. Two changes to `config_generator.py`:

1. Enable on the HTTP connection manager (already default, just needs to not be suppressed)
2. Add `%REQ(X-REQUEST-ID)%` to the access log JSON format in `_build_access_log()`

```yaml
# In generated envoy config, access log format gains:
"request_id": "%REQ(X-REQUEST-ID)%"
```

Vector already parses this field — `.request_id = parsed.request_id` in `vector.yaml` line 83.

### FastAPI auto-instrumentation

```python
# tracing.py (same pattern in CP and DP)
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

def init_tracing(app, service_name: str):
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "..."))
    ))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
```

One call in `app.py` (CP) and `main.py` (DP). All routes get spans automatically.

Default endpoints differ per plane:
- **CP**: `http://jaeger:4317` (gRPC) — Jaeger all-in-one
- **DP**: `http://log-store:5081/api/default/v1/traces` (HTTP) — OpenObserve OTLP ingestion (uses `opentelemetry-exporter-otlp-proto-http` instead of gRPC)

### httpx propagation (CP → DP)

```python
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
HTTPXClientInstrumentor().instrument()
```

After this, every httpx request from `proxy_to_warden()` automatically includes `traceparent` header. Warden's FastAPI instrumentation picks it up and links spans.

### ARQ job trace propagation

```python
# When enqueuing
from opentelemetry.context import get_current
ctx = get_current()  # capture trace context
await arq.enqueue_job("provision_server", server_id, _job_id=..., _meta={"trace_ctx": serialize(ctx)})

# In worker
async def provision_server(ctx, server_id):
    trace_ctx = deserialize(ctx["job_meta"]["trace_ctx"])
    with tracer.start_as_current_span("provision_server", context=trace_ctx):
        ...
```

### Structured log enrichment

Add trace_id to existing log format so grep-based debugging also benefits:

```python
import logging
from opentelemetry import trace

class TraceIdFilter(logging.Filter):
    def filter(self, record):
        span = trace.get_current_span()
        record.trace_id = format(span.get_span_context().trace_id, '032x') if span else '-'
        return True
```

## Migration Phases

### Phase 1: Envoy request IDs + log correlation (2-3 days)

- Enable `x-request-id` generation in Envoy config
- Add `request_id` to Envoy access log JSON format
- Vector starts receiving real request IDs (zero Vector changes needed)
- Add request_id to warden ext_authz logs
- **Result**: all Envoy access logs and ext_authz logs share a request ID per request

### Phase 2: OTel in CP + Jaeger (3-4 days)

- Add OTel packages to CP requirements
- Init tracing in CP `app.py`
- FastAPI auto-instrumentation on all CP routes
- httpx auto-instrumentation (CP→DP calls get traceparent)
- Add Jaeger all-in-one to CP docker-compose (dev)
- Enrich CP structured logs with trace_id
- **Result**: CP requests visible in Jaeger UI; CP→DP calls carry traceparent

### Phase 3: OTel in DP + OpenObserve traces (2-3 days)

- Add OTel packages to DP requirements
- Init tracing in warden `main.py`, exporting spans to local OpenObserve via OTLP/HTTP
- FastAPI auto-instrumentation on warden routes
- Warden picks up traceparent from CP calls → logs the same trace_id (spans stay in local OpenObserve)
- Enrich warden logs with trace_id
- No new containers — OpenObserve already runs under the `auditing` profile
- **Result**: DP traces queryable in OpenObserve alongside logs; shared trace_id with CP for cross-plane correlation via log search

### Phase 4: Background task + ARQ propagation (2-3 days)

- Propagate span context into `asyncio.create_task` calls
- Propagate trace context in ARQ job metadata
- Worker extracts context and creates linked spans
- **Result**: async operations (provisioning, config sync) appear as children of the originating request

### Phase 5: Production backend (1 week, optional)

- Evaluate Grafana Cloud free tier (50GB traces/mo) vs self-hosted Jaeger with Elasticsearch
- Sampling configuration (head-based: sample N% of traces; tail-based: keep all error traces)
- Retention policies
- Dashboard/alerting on trace data (p99 latency, error rates per service)

## Costs

### Resource overhead

| Item | Cost |
|------|------|
| Jaeger all-in-one (CP, dev) | ~100-200MB RAM, single container, $0 |
| OpenObserve trace ingestion (DP) | Already running — trace data shares existing OO resource budget |
| OTel SDK per request | <1ms latency overhead (OTel project benchmarks) |
| Python packages | 6 packages, ~5MB installed |
| Span storage | ~1KB/span, ~5 spans/request → ~5KB/request |

### Storage estimates

| Scale | Daily storage | Monthly |
|-------|--------------|---------|
| 100 req/hr (dev) | ~12MB | ~360MB |
| 1,000 req/hr (staging) | ~120MB | ~3.6GB |
| 10,000 req/hr (prod) | ~1.2GB | ~36GB |

DP trace storage is governed by OpenObserve's existing `ZO_COMPACT_DATA_RETENTION_DAYS` setting (default 30 days), same as logs.

### Backend options by plane

**DP**: OpenObserve (already deployed). No new infrastructure. Traces are stored alongside logs and queryable via the same OO SQL API. Retention controlled by existing `LOG_RETENTION_DAYS` env var.

**CP**:

| Option | Cost | Persistence | Notes |
|--------|------|------------|-------|
| Jaeger all-in-one (in-memory) | $0 | None (restart loses data) | Good for dev |
| Jaeger + Badger (local disk) | $0 + disk | Days | Good for staging |
| Jaeger + Elasticsearch | ES cluster cost | Weeks/months | Good for prod |
| Grafana Cloud free tier | $0 | 50GB traces/mo | Easiest prod option |
| Grafana Cloud paid | $5/GB after free tier | Configurable | If free tier exceeded |

## Effort Estimate

- Phase 1: 2-3 days (Envoy request IDs)
- Phase 2: 3-4 days (CP OTel + Jaeger)
- Phase 3: 2-3 days (DP OTel + cross-plane)
- Phase 4: 2-3 days (background/ARQ propagation)
- Phase 5: 1 week (production backend, optional)
- **Total: ~2-3 weeks** (phases 1-4), +1 week for production backend

## Risks

| Risk | Mitigation |
|------|------------|
| OTel SDK overhead on hot paths | <1ms per span; auto-instrumentation is battle-tested; disable in benchmarks if needed |
| Trace backend unavailable | Tracing is observability-only — if Jaeger/OpenObserve is down, requests still work, spans are dropped |
| DP trace volume bloating OpenObserve | Shares existing retention policy; sampling can reduce volume; OO compacts old data automatically |
| Span volume in production | Head-based sampling (e.g. 10% of traces); tail-based sampling keeps all errors |
| ARQ job context serialization | Use standard OTel context propagation; trace_ctx is just a string in job metadata |
| Package version conflicts | Pin OTel packages together; they release in lockstep |
| Envoy x-request-id format | Use Envoy's default UUID format; no custom ID generation needed |
