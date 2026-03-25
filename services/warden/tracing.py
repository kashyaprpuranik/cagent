"""OpenTelemetry tracing setup for warden.

Exports spans via OTLP HTTP. Tracing endpoint is configurable via
OTEL_EXPORTER_OTLP_ENDPOINT env var (no longer tied to OpenObserve).
Opt-in: controlled by OTEL_ENABLED constant (env var).
"""

import logging
import os

from constants import (
    DATAPLANE_MODE,
    OTEL_ENABLED,
)

logger = logging.getLogger(__name__)

# OTLP endpoint — defaults to a standard OTLP collector port.
# Override with OTEL_EXPORTER_OTLP_ENDPOINT env var.
OTEL_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces")


def setup_tracing(app):
    """Instrument the FastAPI app with OpenTelemetry tracing.

    No-op when OTEL_ENABLED is falsy.  Otherwise configures a
    TracerProvider that exports spans via OTLP HTTP and instruments
    FastAPI, requests, and logging.
    """
    if not OTEL_ENABLED:
        logger.info("OpenTelemetry tracing disabled (OTEL_ENABLED is not set)")
        return

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create(
        {
            "service.name": "warden",
            "service.version": "1.0.0",
            "deployment.environment": DATAPLANE_MODE,
        }
    )

    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(
        endpoint=OTEL_ENDPOINT,
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Instrument FastAPI, outbound requests, and logging
    FastAPIInstrumentor().instrument_app(app)
    RequestsInstrumentor().instrument()
    LoggingInstrumentor().instrument()

    logger.info("OpenTelemetry tracing enabled — exporting to %s", OTEL_ENDPOINT)
