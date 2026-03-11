"""Unit tests for OpenTelemetry tracing setup."""

import importlib
import os
import sys
from unittest.mock import MagicMock, patch

# Mock docker before importing warden modules
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = MagicMock(containers=MagicMock(list=MagicMock(return_value=[])))
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))


def _build_otel_mocks():
    """Create mock OTel modules and return key mock objects for assertions."""
    # Top-level modules
    otel = MagicMock()
    otel_sdk = MagicMock()
    otel_sdk_trace = MagicMock()
    otel_sdk_trace_export = MagicMock()
    otel_sdk_resources = MagicMock()
    otel_exporter = MagicMock()
    otel_exporter_otlp = MagicMock()
    otel_exporter_otlp_proto = MagicMock()
    otel_exporter_otlp_proto_http = MagicMock()
    otel_exporter_otlp_proto_http_trace_exporter = MagicMock()
    otel_inst_fastapi = MagicMock()
    otel_inst_requests = MagicMock()
    otel_inst_logging = MagicMock()
    otel_instrumentation = MagicMock()

    modules = {
        "opentelemetry": otel,
        "opentelemetry.trace": otel.trace,
        "opentelemetry.sdk": otel_sdk,
        "opentelemetry.sdk.resources": otel_sdk_resources,
        "opentelemetry.sdk.trace": otel_sdk_trace,
        "opentelemetry.sdk.trace.export": otel_sdk_trace_export,
        "opentelemetry.exporter": otel_exporter,
        "opentelemetry.exporter.otlp": otel_exporter_otlp,
        "opentelemetry.exporter.otlp.proto": otel_exporter_otlp_proto,
        "opentelemetry.exporter.otlp.proto.http": otel_exporter_otlp_proto_http,
        "opentelemetry.exporter.otlp.proto.http.trace_exporter": otel_exporter_otlp_proto_http_trace_exporter,
        "opentelemetry.instrumentation": otel_instrumentation,
        "opentelemetry.instrumentation.fastapi": otel_inst_fastapi,
        "opentelemetry.instrumentation.requests": otel_inst_requests,
        "opentelemetry.instrumentation.logging": otel_inst_logging,
    }

    # Wire up the names that tracing.py imports via `from ... import ...`
    otel_sdk_trace.TracerProvider = MagicMock()
    otel_sdk_trace_export.BatchSpanProcessor = MagicMock()
    otel_sdk_resources.Resource = MagicMock()
    otel_exporter_otlp_proto_http_trace_exporter.OTLPSpanExporter = MagicMock()
    otel_inst_fastapi.FastAPIInstrumentor = MagicMock()
    otel_inst_requests.RequestsInstrumentor = MagicMock()
    otel_inst_logging.LoggingInstrumentor = MagicMock()

    # `from opentelemetry import trace` resolves to otel.trace
    # Wire it so `trace.set_tracer_provider` is callable
    otel.trace = MagicMock()

    # Re-bind after override
    modules["opentelemetry"] = otel
    modules["opentelemetry.trace"] = otel.trace

    return modules, {
        "trace": otel.trace,
        "TracerProvider": otel_sdk_trace.TracerProvider,
        "BatchSpanProcessor": otel_sdk_trace_export.BatchSpanProcessor,
        "Resource": otel_sdk_resources.Resource,
        "OTLPSpanExporter": otel_exporter_otlp_proto_http_trace_exporter.OTLPSpanExporter,
        "FastAPIInstrumentor": otel_inst_fastapi.FastAPIInstrumentor,
        "RequestsInstrumentor": otel_inst_requests.RequestsInstrumentor,
        "LoggingInstrumentor": otel_inst_logging.LoggingInstrumentor,
    }


class TestSetupTracingDisabled:
    """When OTEL_ENABLED is false, setup_tracing should be a no-op."""

    def test_noop_when_disabled(self):
        import tracing

        with patch.object(tracing, "OTEL_ENABLED", False):
            app = MagicMock()
            tracing.setup_tracing(app)

        # No OTel modules should have been imported / no instrumentation
        app.assert_not_called()


class TestSetupTracingEnabled:
    """When OTEL_ENABLED is true, setup_tracing should configure OTel."""

    def _run_with_mocks(self, dataplane_mode="connected", openobserve_url="http://log-store:5080"):
        """Helper: run setup_tracing with mocked OTel modules and return mocks."""
        otel_modules, mocks = _build_otel_mocks()

        import tracing

        with (
            patch.object(tracing, "OTEL_ENABLED", True),
            patch.object(tracing, "OPENOBSERVE_URL", openobserve_url),
            patch.object(tracing, "OPENOBSERVE_USER", "admin@cagent.local"),
            patch.object(tracing, "OPENOBSERVE_PASSWORD", "test-password"),
            patch.object(tracing, "DATAPLANE_MODE", dataplane_mode),
            patch.dict(sys.modules, otel_modules),
        ):
            # Force re-import of OTel inside the function
            app = MagicMock()
            tracing.setup_tracing(app)

        return app, mocks

    def test_configures_tracer_provider(self):
        app, mocks = self._run_with_mocks()

        # TracerProvider was created and registered
        mocks["TracerProvider"].assert_called_once()
        mocks["trace"].set_tracer_provider.assert_called_once_with(
            mocks["TracerProvider"].return_value
        )

        # BatchSpanProcessor was created with the exporter and added to provider
        mocks["BatchSpanProcessor"].assert_called_once_with(
            mocks["OTLPSpanExporter"].return_value
        )
        mocks["TracerProvider"].return_value.add_span_processor.assert_called_once_with(
            mocks["BatchSpanProcessor"].return_value
        )

        # Instrumentors were called
        mocks["FastAPIInstrumentor"].return_value.instrument_app.assert_called_once_with(app)
        mocks["RequestsInstrumentor"].return_value.instrument.assert_called_once()
        mocks["LoggingInstrumentor"].return_value.instrument.assert_called_once()

    def test_otlp_endpoint_constructed_correctly(self):
        _, mocks = self._run_with_mocks(openobserve_url="http://log-store:5080")

        call_kwargs = mocks["OTLPSpanExporter"].call_args[1]
        assert call_kwargs["endpoint"] == "http://log-store:5080/api/default/v1/traces"

    def test_otlp_basic_auth_header(self):
        _, mocks = self._run_with_mocks()

        call_kwargs = mocks["OTLPSpanExporter"].call_args[1]
        assert "Authorization" in call_kwargs["headers"]
        assert call_kwargs["headers"]["Authorization"].startswith("Basic ")

    def test_service_name_resource_attribute(self):
        _, mocks = self._run_with_mocks(dataplane_mode="connected")

        mocks["Resource"].create.assert_called_once()
        attrs = mocks["Resource"].create.call_args[0][0]
        assert attrs["service.name"] == "warden"
        assert attrs["service.version"] == "1.0.0"
        assert attrs["deployment.environment"] == "connected"

        # TracerProvider was created with the resource
        mocks["TracerProvider"].assert_called_once_with(
            resource=mocks["Resource"].create.return_value
        )
