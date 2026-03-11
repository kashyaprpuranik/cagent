# Distributed Tracing Plan

OpenTelemetry-based request tracing across control plane and data plane.

## Motivation

Debugging cross-service issues today requires manually grepping logs across multiple containers with no request correlation. A single user action (e.g. "provision a cell") touches CP API -> CP background task -> ARQ job -> Hetzner API -> warden heartbeat -> config generation -- but there's no thread connecting these steps. When something fails mid-chain, finding the root cause means opening 4+ log streams and matching timestamps by eye.

Distributed tracing solves this by assigning a single trace ID to each request and propagating it across service boundaries. Every span (unit of work) links back to the trace, giving a full timeline of what happened, where it stalled, and what failed.

### Goals

1. **Request correlation**: link all log lines for a single request across services
2. **End-to-end observability**: see the full lifecycle of operations like cell provisioning, config sync, credential injection
3. **CP<>DP correlation**: trace a CP API call through to the warden action it triggers
4. **Debugging aid**: pinpoint latency bottlenecks and failure points without manual log correlation

## Architecture

```
                         +--------------------------------------+
                         |           Control Plane               |
                         |                                      |
  User --> CP API ------>|  FastAPI --> background tasks --> ARQ |
           (traceparent) |    |              |                   |
                         |    |  trace_id    |  trace_id in      |
                         |    |  in logs     |  job metadata     |
                         +----|--------------|----- ------------+
                              |
                              |   OTel SDK exports spans
                              v
                         +------------------+
                         |  Jaeger (CP-only) |
                         |  OTLP/gRPC :4317  |
                         |  UI on :16686     |
                         +------------------+


                         +--------------------------------------+
                         |           Data Plane                  |
                         |                                      |
  Envoy --> ext_authz -->|  Warden FastAPI    config_generator  |
  (x-request-id)         |    |                                 |
                         |    |  trace_id in logs               |
                         |    |                                 |
                         |    |  OTel SDK exports spans          |
                         |    v                                 |
                         |  OpenObserve (OTLP/HTTP :5080)       |
                         +--------------------------------------+
```

**CP** uses Jaeger (dev) or GCP Cloud Trace (prod) as the trace backend.
**DP** uses OpenObserve (already deployed under the `auditing` profile) -- no new containers.

Cross-plane correlation works via shared `trace_id`: CP attaches `traceparent` to outbound calls, warden extracts it and logs the same `trace_id`. Full waterfall views are per-plane; cross-plane correlation is via log search on the shared trace ID.

## Phases

### Phase 1: Envoy request IDs + log correlation -- DONE

- Added `request_id` to Envoy access log JSON format (PR #105)
- Vector picks up real request IDs automatically (zero Vector changes)
- **Result**: every Envoy access log line has a UUID request_id

### Phase 2: OTel in CP + Jaeger (3-4 days)

- Add OTel packages to CP requirements
- Init tracing in CP `app.py`
- FastAPI auto-instrumentation on all CP routes
- httpx auto-instrumentation (CP->DP calls get traceparent)
- Add Jaeger all-in-one to CP docker-compose (dev)
- Enrich CP structured logs with trace_id
- **Result**: CP requests visible in Jaeger UI; CP->DP calls carry traceparent

### Phase 3: OTel in DP + OpenObserve traces (2-3 days)

- Add OTel packages to DP requirements
- Init tracing in warden `main.py`, exporting spans to local OpenObserve via OTLP/HTTP
- FastAPI auto-instrumentation on warden routes
- Warden picks up traceparent from CP calls -> logs the same trace_id (spans stay in local OpenObserve)
- Enrich warden logs with trace_id
- No new containers -- OpenObserve already runs under the `auditing` profile
- **Result**: DP traces queryable in OpenObserve alongside logs; shared trace_id with CP for cross-plane correlation via log search

### Phase 4: Background task + ARQ propagation (2-3 days)

- Propagate span context into `asyncio.create_task` calls
- Propagate trace context in ARQ job metadata
- Worker extracts context and creates linked spans
- **Result**: async operations (provisioning, config sync) appear as children of the originating request

### Phase 5: Production backend (1 week)

- CP: switch from Jaeger to GCP Cloud Trace via `opentelemetry-exporter-gcp-trace`
  - Cloud Trace accepts OTLP natively, no collector needed
  - Uses existing GCP project service accounts (cagent-control-dev/staging/prod)
  - Free tier: 2.5M spans/month ingestion, 5M spans stored
- DP: traces stay in local OpenObserve (already production-ready)
- Sampling configuration (head-based: sample N% of traces; tail-based: keep all error traces)
- Retention: Cloud Trace retains 30 days by default; OpenObserve governed by `ZO_COMPACT_DATA_RETENTION_DAYS`

## Costs

### Resource overhead

| Item | Cost |
|------|------|
| Jaeger all-in-one (CP, dev only) | ~100-200MB RAM, single container, $0 |
| GCP Cloud Trace (CP, prod) | Free up to 2.5M spans/month; $0.20/M spans after |
| OpenObserve trace ingestion (DP) | Already running -- trace data shares existing OO resource budget |
| OTel SDK per request | <1ms latency overhead |
| Python packages | 6 packages, ~5MB installed |
| Span storage | ~1KB/span, ~5 spans/request, ~5KB/request |

### Storage estimates

| Scale | Daily storage | Monthly |
|-------|--------------|---------|
| 100 req/hr (dev) | ~12MB | ~360MB |
| 1,000 req/hr (staging) | ~120MB | ~3.6GB |
| 10,000 req/hr (prod) | ~1.2GB | ~36GB |

### Backend by plane

**DP**: OpenObserve (already deployed). No new infrastructure. Traces stored alongside logs and queryable via the same OO SQL API. Retention controlled by existing `LOG_RETENTION_DAYS` env var.

**CP**:

| Environment | Backend | Cost | Notes |
|-------------|---------|------|-------|
| Dev | Jaeger all-in-one (in-memory) | $0 | Restart loses data, fine for dev |
| Staging | GCP Cloud Trace | $0 (free tier) | 2.5M spans/month free |
| Prod | GCP Cloud Trace | $0-5/month est. | $0.20/M spans after free tier |

## Effort Estimate

- Phase 1: DONE (Envoy request IDs)
- Phase 2: 3-4 days (CP OTel + Jaeger)
- Phase 3: 2-3 days (DP OTel + OpenObserve)
- Phase 4: 2-3 days (background/ARQ propagation)
- Phase 5: 1 week (GCP Cloud Trace for prod CP)
- **Total remaining: ~2-3 weeks**

## Risks

| Risk | Mitigation |
|------|------------|
| OTel SDK overhead on hot paths | <1ms per span; auto-instrumentation is battle-tested; disable in benchmarks if needed |
| Trace backend unavailable | Tracing is observability-only -- if Jaeger/OO/Cloud Trace is down, requests still work, spans are dropped |
| DP trace volume bloating OpenObserve | Shares existing retention policy; sampling can reduce volume; OO compacts old data automatically |
| Span volume in production | Head-based sampling (e.g. 10% of traces); tail-based sampling keeps all errors |
| ARQ job context serialization | Standard OTel context propagation; trace_ctx is just a string in job metadata |
| Package version conflicts | Pin OTel packages together; they release in lockstep |
