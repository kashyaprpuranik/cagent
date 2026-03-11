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
                         │    │              │                   │
                         │    │  OTel SDK exports spans           │
                         │    ▼                                  │
                         │  Google Cloud Trace (serverless)      │
                         └──────────────────────────────────────┘


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

Each plane stores traces in its own backend. The CP exports spans to **Google Cloud Trace** — a serverless GCP service, no infrastructure to manage. The DP exports spans to the existing **OpenObserve** instance (`log-store` container, already running under the `auditing` profile) — no new containers needed.

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
opentelemetry-exporter-otlp-proto-http
```

### CP-specific

- `tracing.py` module: OTel SDK init, Google Cloud Trace exporter, helper to inject trace_id into structured logs
- `opentelemetry-exporter-gcp-trace` package for Cloud Trace export
- FastAPI auto-instrumentation (all routes get spans automatically)
- httpx auto-instrumentation (`proxy_to_warden()` propagates `traceparent` to DP)
- ARQ job trace propagation: `trace_id` stored in job metadata, linked as child span in worker
- Background task trace propagation: capture span context before `asyncio.create_task`, restore in task
- No new containers — Cloud Trace is a serverless GCP service, uses existing service account credentials

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
# tracing.py (same pattern in CP and DP, different exporter)
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

def init_tracing(app, service_name: str, exporter):
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
```

One call in `app.py` (CP) and `main.py` (DP). All routes get spans automatically.

Exporters differ per plane:
- **CP**: `opentelemetry-exporter-gcp-trace` — exports to Google Cloud Trace using existing GCP service account credentials. Serverless, no endpoint to configure.
- **DP**: `opentelemetry-exporter-otlp-proto-http` → `http://log-store:5081/api/default/v1/traces` — exports to local OpenObserve via OTLP/HTTP

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

### Phase 2: OTel in CP + Google Cloud Trace (3-4 days)

- Add OTel packages + `opentelemetry-exporter-gcp-trace` to CP requirements
- Init tracing in CP `app.py` with Cloud Trace exporter
- FastAPI auto-instrumentation on all CP routes
- httpx auto-instrumentation (CP→DP calls get traceparent)
- Enrich CP structured logs with trace_id
- No new containers — Cloud Trace is serverless, uses existing GCP service account
- **Result**: CP requests visible in GCP Console → Trace; CP→DP calls carry traceparent

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

### Phase 5: Production tuning (3-4 days, optional)

- Sampling configuration (head-based: sample N% of traces; tail-based: keep all error traces)
- Cloud Trace alerting policies (latency thresholds, error rate spikes)
- OpenObserve retention tuning for DP trace data
- Dashboard for trace-derived metrics (p99 latency, error rates per service)

## Costs

### Resource overhead

| Item | Cost |
|------|------|
| Google Cloud Trace (CP) | $0.20/million spans; first 2.5M spans/mo free. Serverless — no container, no RAM |
| OpenObserve trace ingestion (DP) | Already running — trace data shares existing OO resource budget |
| OTel SDK per request | <1ms latency overhead (OTel project benchmarks) |
| Python packages | 6 packages + gcp-trace exporter, ~5MB installed |
| Span storage | ~1KB/span, ~5 spans/request → ~5KB/request |

### CP cost estimate (Google Cloud Trace)

| Scale | Spans/month | Monthly cost |
|-------|------------|-------------|
| 100 req/hr (dev) | ~360K | $0 (free tier) |
| 1,000 req/hr (staging) | ~3.6M | $0.22 |
| 10,000 req/hr (prod) | ~36M | $6.70 |

### DP storage estimate (OpenObserve)

| Scale | Daily | Monthly |
|-------|-------|---------|
| 100 req/hr | ~12MB | ~360MB |
| 1,000 req/hr | ~120MB | ~3.6GB |

DP trace storage is governed by OpenObserve's existing `ZO_COMPACT_DATA_RETENTION_DAYS` setting (default 30 days), same as logs.

### Backend summary

- **CP**: Google Cloud Trace — serverless, uses existing GCP service account, viewable in GCP Console. No new infrastructure.
- **DP**: OpenObserve (already deployed) — traces stored alongside logs, queryable via same OO SQL API. No new containers.

## Effort Estimate

- Phase 1: 2-3 days (Envoy request IDs)
- Phase 2: 3-4 days (CP OTel + Cloud Trace)
- Phase 3: 2-3 days (DP OTel + OpenObserve)
- Phase 4: 2-3 days (background/ARQ propagation)
- Phase 5: 3-4 days (production tuning, optional)
- **Total: ~2-3 weeks** (phases 1-4), +3-4 days for production tuning

## Risks

| Risk | Mitigation |
|------|------------|
| OTel SDK overhead on hot paths | <1ms per span; auto-instrumentation is battle-tested; disable in benchmarks if needed |
| Trace backend unavailable | Tracing is observability-only — if Cloud Trace/OpenObserve is down, requests still work, spans are dropped |
| DP trace volume bloating OpenObserve | Shares existing retention policy; sampling can reduce volume; OO compacts old data automatically |
| Span volume in production | Head-based sampling (e.g. 10% of traces); tail-based sampling keeps all errors |
| ARQ job context serialization | Use standard OTel context propagation; trace_ctx is just a string in job metadata |
| Package version conflicts | Pin OTel packages together; they release in lockstep |
| Envoy x-request-id format | Use Envoy's default UUID format; no custom ID generation needed |
