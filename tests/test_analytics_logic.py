import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Add services/warden to sys.path so 'constants' resolves at import time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

# Mock docker client before importing analytics (constants.py calls docker.from_env() at module scope)
mock_docker = MagicMock()
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = mock_docker
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception
mock_docker.containers.list.return_value = []

from routers import analytics


# ---------------------------------------------------------------------------
# Widget registry tests
# ---------------------------------------------------------------------------

def test_widget_registry_has_all_types():
    expected = {
        "blocked_domains_top",
        "blocked_timeseries",
        "bandwidth_by_domain",
        "requests_by_status",
        "request_volume",
        "latency_by_domain",
        "credential_usage",
    }
    assert set(analytics.WIDGET_REGISTRY.keys()) == expected


def test_widget_registry_entries_have_required_keys():
    required = {"name", "category", "visualization", "default_params", "columns", "query_fn"}
    for widget_id, spec in analytics.WIDGET_REGISTRY.items():
        missing = required - set(spec.keys())
        assert not missing, f"Widget {widget_id} missing keys: {missing}"


def test_widget_registry_columns_have_required_keys():
    for widget_id, spec in analytics.WIDGET_REGISTRY.items():
        for col in spec["columns"]:
            assert "name" in col, f"Widget {widget_id}: column missing 'name'"
            assert "type" in col, f"Widget {widget_id}: column missing 'type'"
            assert "role" in col, f"Widget {widget_id}: column missing 'role'"


# ---------------------------------------------------------------------------
# /analytics/types endpoint
# ---------------------------------------------------------------------------

def test_get_widget_types():
    result = analytics.get_widget_types()
    assert "widgets" in result
    widgets = result["widgets"]
    assert len(widgets) == 7
    # Verify each widget has expected fields
    for w in widgets:
        assert "type" in w
        assert "name" in w
        assert "category" in w
        assert "visualization" in w
        assert "default_params" in w
        assert "columns" in w
    # query_fn should NOT be exposed
    for w in widgets:
        assert "query_fn" not in w


# ---------------------------------------------------------------------------
# /analytics/query endpoint
# ---------------------------------------------------------------------------

@patch("routers.analytics._oo_available", return_value=False)
def test_query_widget_oo_unavailable(mock_oo):
    """When OO is unavailable, return empty rows with a note."""
    body = analytics.WidgetQueryRequest(type="blocked_domains_top", params={"window_hours": 1})
    result = analytics.query_widget(body)

    assert result["widget"] == "blocked_domains_top"
    assert result["visualization"] == "bar_horizontal"
    assert result["rows"] == []
    assert "note" in result["meta"]
    assert "unavailable" in result["meta"]["note"].lower()


@patch("routers.analytics._oo_available", return_value=True)
@patch("routers.analytics._oo_query")
def test_query_blocked_domains_top(mock_oo_query, mock_oo_avail):
    mock_oo_query.return_value = [
        {"domain": "evil.com", "count": 42, "last_seen": "2026-03-11T00:00:00Z"},
        {"domain": "bad.io", "count": 10, "last_seen": "2026-03-11T01:00:00Z"},
    ]
    body = analytics.WidgetQueryRequest(type="blocked_domains_top", params={"window_hours": 24, "limit": 10})
    result = analytics.query_widget(body)

    assert result["widget"] == "blocked_domains_top"
    assert len(result["rows"]) == 2
    assert result["rows"][0] == ["evil.com", 42, "2026-03-11T00:00:00Z"]
    assert result["rows"][1] == ["bad.io", 10, "2026-03-11T01:00:00Z"]


@patch("routers.analytics._oo_available", return_value=True)
@patch("routers.analytics._oo_query")
def test_query_bandwidth_by_domain(mock_oo_query, mock_oo_avail):
    mock_oo_query.return_value = [
        {"domain": "example.com", "bytes_sent": 1000, "bytes_received": 500, "total_bytes": 1500},
    ]
    body = analytics.WidgetQueryRequest(type="bandwidth_by_domain")
    result = analytics.query_widget(body)

    assert result["widget"] == "bandwidth_by_domain"
    assert len(result["rows"]) == 1
    assert result["rows"][0] == ["example.com", 1000, 500, 1500]


@patch("routers.analytics._oo_available", return_value=True)
@patch("routers.analytics._oo_query")
def test_query_requests_by_status(mock_oo_query, mock_oo_avail):
    mock_oo_query.return_value = [
        {"status_code": 200, "count": 100},
        {"status_code": 403, "count": 5},
    ]
    body = analytics.WidgetQueryRequest(type="requests_by_status")
    result = analytics.query_widget(body)

    assert result["widget"] == "requests_by_status"
    assert len(result["rows"]) == 2
    assert result["rows"][0] == [200, 100]


@patch("routers.analytics._oo_available", return_value=True)
@patch("routers.analytics._oo_query")
def test_query_latency_by_domain(mock_oo_query, mock_oo_avail):
    mock_oo_query.return_value = [
        {"domain": "slow.com", "request_count": 50, "avg_ms": 123.456, "max_ms": 500},
    ]
    body = analytics.WidgetQueryRequest(type="latency_by_domain")
    result = analytics.query_widget(body)

    assert result["widget"] == "latency_by_domain"
    assert len(result["rows"]) == 1
    assert result["rows"][0] == ["slow.com", 50, 123.5, 500]  # avg_ms rounded to 1 decimal


@patch("routers.analytics._oo_available", return_value=True)
@patch("routers.analytics._oo_query")
def test_query_credential_usage(mock_oo_query, mock_oo_avail):
    mock_oo_query.return_value = [
        {"domain": "api.example.com", "total_requests": 200, "injected_count": 150},
    ]
    body = analytics.WidgetQueryRequest(type="credential_usage")
    result = analytics.query_widget(body)

    assert result["widget"] == "credential_usage"
    assert result["rows"][0] == ["api.example.com", 200, 150]


@patch("routers.analytics._oo_available", return_value=True)
@patch("routers.analytics._oo_query")
def test_query_blocked_timeseries(mock_oo_query, mock_oo_avail):
    mock_oo_query.return_value = [
        {"bucket": 1000000, "count": 5},
        {"bucket": 2000000, "count": 3},
    ]
    body = analytics.WidgetQueryRequest(type="blocked_timeseries", params={"window_hours": 1, "buckets": 6})
    result = analytics.query_widget(body)

    assert result["widget"] == "blocked_timeseries"
    assert len(result["rows"]) == 2


@patch("routers.analytics._oo_available", return_value=True)
@patch("routers.analytics._oo_query")
def test_query_request_volume(mock_oo_query, mock_oo_avail):
    mock_oo_query.return_value = [
        {"bucket": 1000000, "total": 100, "blocked": 5, "rate_limited": 2},
    ]
    body = analytics.WidgetQueryRequest(type="request_volume")
    result = analytics.query_widget(body)

    assert result["widget"] == "request_volume"
    assert result["visualization"] == "stacked_area"
    assert result["rows"][0] == [1000000, 100, 5, 2]


def test_query_unknown_widget():
    body = analytics.WidgetQueryRequest(type="nonexistent")
    with pytest.raises(Exception) as exc_info:
        analytics.query_widget(body)
    assert exc_info.value.status_code == 400


def test_query_default_params_used():
    """When no params provided, default_params from registry are used."""
    with patch("routers.analytics._oo_available", return_value=True), \
         patch("routers.analytics._oo_query", return_value=[]) as mock_q:
        body = analytics.WidgetQueryRequest(type="blocked_domains_top")
        result = analytics.query_widget(body)
        assert result["meta"]["window_hours"] == 24
        assert result["meta"]["limit"] == 10


def test_query_params_override_defaults():
    """User params should override default_params."""
    with patch("routers.analytics._oo_available", return_value=True), \
         patch("routers.analytics._oo_query", return_value=[]) as mock_q:
        body = analytics.WidgetQueryRequest(type="blocked_domains_top", params={"window_hours": 6, "limit": 5})
        result = analytics.query_widget(body)
        assert result["meta"]["window_hours"] == 6
        assert result["meta"]["limit"] == 5


# ---------------------------------------------------------------------------
# /analytics/diagnose endpoint (kept as-is)
# ---------------------------------------------------------------------------

@patch("routers.analytics.subprocess.run")
@patch("routers.analytics.Path")
def test_diagnose_domain(mock_path, mock_subprocess):
    """Test diagnose endpoint with mocked OO and DNS."""
    mock_container = MagicMock()
    mock_container.logs.return_value = b""

    with patch("routers.analytics.docker_client") as mock_dc:
        mock_dc.containers.get.return_value = mock_container

        # Setup subprocess mock for DNS
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Address: 1.2.3.4"
        mock_subprocess.return_value = mock_proc

        # Setup Path mock
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.read_text.return_value = "domains:\n  - domain: allowed.com"
        mock_path.return_value = mock_path_instance

        # Mock OO query for recent requests
        with patch("routers.analytics.query_openobserve", create=True) as mock_oo_q:
            result = analytics.diagnose_domain(domain="blocked.com")

        assert result["domain"] == "blocked.com"
        assert not result["in_allowlist"]
        assert result["dns_result"] == "1.2.3.4"
