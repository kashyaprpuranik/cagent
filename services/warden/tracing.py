"""OpenTelemetry tracing setup for warden.

Exports spans to the local OpenObserve instance via OTLP HTTP.
Opt-in: controlled by OTEL_ENABLED constant (env var).
"""

import logging

from constants import (
    DATAPLANE_MODE,
    OTEL_ENABLED,
    OPENOBSERVE_PASSWORD,
    OPENOBSERVE_URL,
    OPENOBSERVE_USER,
)

logger = logging.getLogger(__name__)


def setup_tracing(app):
    """Instrument the FastAPI app with OpenTelemetry tracing.

    No-op when OTEL_ENABLED is falsy.  Otherwise configures a
    TracerProvider that exports spans to OpenObserve via OTLP HTTP
    and instruments FastAPI, requests, and logging.
    """
    if not OTEL_ENABLED:
        logger.info("OpenTelemetry tracing disabled (OTEL_ENABLED is not set)")
        return

    from base64 import b64encode

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

    # Basic auth header for OpenObserve OTLP endpoint
    credentials = b64encode(f"{OPENOBSERVE_USER}:{OPENOBSERVE_PASSWORD}".encode()).decode()
    endpoint = f"{OPENOBSERVE_URL}/api/default/v1/traces"

    exporter = OTLPSpanExporter(
        endpoint=endpoint,
        headers={"Authorization": f"Basic {credentials}"},
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # Instrument FastAPI, outbound requests, and logging
    FastAPIInstrumentor().instrument_app(app)
    RequestsInstrumentor().instrument()
    LoggingInstrumentor().instrument()

    logger.info("OpenTelemetry tracing enabled — exporting to %s", endpoint)
