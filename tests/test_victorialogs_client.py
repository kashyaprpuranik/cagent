"""Unit tests for the local VictoriaLogs client."""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# Mock docker before importing warden modules
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = MagicMock(containers=MagicMock(list=MagicMock(return_value=[])))
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

from victorialogs_client import datetime_to_us, is_healthy, now_us, query_logs, query_stats, us_to_iso


class TestDatetimeConversion:
    """Test time conversion helpers."""

    def test_datetime_to_us_epoch(self):
        """Epoch should convert to 0."""
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        assert datetime_to_us(epoch) == 0

    def test_datetime_to_us_known_value(self):
        """A known datetime should produce the correct microsecond value."""
        dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        expected_us = int(dt.timestamp() * 1_000_000)
        assert datetime_to_us(dt) == expected_us

    def test_now_us_is_recent(self):
        """now_us() should return a value close to the current time."""
        before = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
        result = now_us()
        after = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
        assert before <= result <= after

    def test_us_to_iso_epoch(self):
        """Epoch microseconds should produce ISO timestamp."""
        result = us_to_iso(0)
        assert "1970" in result

    def test_us_to_iso_roundtrip(self):
        """us_to_iso should produce a parseable ISO string."""
        us = 1700000000_000_000  # ~2023-11-14
        iso = us_to_iso(us)
        dt = datetime.fromisoformat(iso)
        assert abs(dt.timestamp() * 1_000_000 - us) < 1_000_000  # within 1s


class TestIsHealthy:
    """Test VL health check."""

    @patch("victorialogs_client.requests.get")
    def test_healthy_returns_true(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        assert is_healthy() is True

    @patch("victorialogs_client.requests.get")
    def test_unhealthy_status_returns_false(self, mock_get):
        mock_get.return_value = MagicMock(status_code=503)
        assert is_healthy() is False

    @patch("victorialogs_client.requests.get")
    def test_connection_error_returns_false(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError("Connection refused")
        assert is_healthy() is False

    @patch("victorialogs_client.requests.get")
    def test_timeout_returns_false(self, mock_get):
        import requests

        mock_get.side_effect = requests.Timeout("Timeout")
        assert is_healthy() is False

    @patch("victorialogs_client.requests.get")
    def test_health_endpoint_url(self, mock_get):
        """Health check should hit /health endpoint."""
        mock_get.return_value = MagicMock(status_code=200)
        is_healthy()
        call_args = mock_get.call_args
        assert "/health" in call_args[0][0]


class TestQueryLogs:
    """Test VL raw log query."""

    @patch("victorialogs_client.requests.get")
    def test_successful_query(self, mock_post):
        """Successful query should return parsed JSON lines."""
        lines = [
            json.dumps({"message": "test log 1", "_time": "2026-01-01T00:00:00Z"}),
            json.dumps({"message": "test log 2", "_time": "2026-01-01T00:01:00Z"}),
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "\n".join(lines)
        mock_post.return_value = mock_response

        result = query_logs("source:envoy", 0, 9999999999)
        assert len(result) == 2
        assert result[0]["message"] == "test log 1"

    @patch("victorialogs_client.requests.get")
    def test_query_sends_correct_params(self, mock_post):
        """Query should send LogsQL and time range as query params."""
        mock_post.return_value = MagicMock(status_code=200, text="")

        query_logs("source:envoy AND log_type:access", 1000, 2000)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert params["query"] == "source:envoy AND log_type:access"
        assert "start" in params
        assert "end" in params

    @patch("victorialogs_client.requests.get")
    def test_failed_query_returns_empty(self, mock_post):
        """Non-200 response should return empty list."""
        mock_post.return_value = MagicMock(status_code=500, text="Internal error")
        result = query_logs("*", 0, 1)
        assert result == []

    @patch("victorialogs_client.requests.get")
    def test_connection_error_returns_empty(self, mock_post):
        """Network error should return empty list, not raise."""
        import requests

        mock_post.side_effect = requests.ConnectionError("VL is down")
        result = query_logs("*", 0, 1)
        assert result == []

    @patch("victorialogs_client.requests.get")
    def test_empty_response_returns_empty(self, mock_post):
        """Empty response should return empty list."""
        mock_post.return_value = MagicMock(status_code=200, text="")
        result = query_logs("*", 0, 1)
        assert result == []

    @patch("victorialogs_client.requests.get")
    def test_no_auth_sent(self, mock_post):
        """VictoriaLogs requires no auth — no auth param should be sent."""
        mock_post.return_value = MagicMock(status_code=200, text="")

        query_logs("*", 0, 1)

        call_kwargs = mock_post.call_args
        auth = call_kwargs.kwargs.get("auth")
        assert auth is None


class TestQueryStats:
    """Test VL stats query."""

    @patch("victorialogs_client.requests.get")
    def test_successful_stats_query(self, mock_post):
        """Successful stats query should return parsed JSON lines."""
        lines = [
            json.dumps({"authority": "evil.com", "count": 42}),
            json.dumps({"authority": "bad.io", "count": 10}),
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "\n".join(lines)
        mock_post.return_value = mock_response

        result = query_stats("source:envoy | stats count() as count by (authority)", 0, 9999999999)
        assert len(result) == 2
        assert result[0]["authority"] == "evil.com"
        assert result[0]["count"] == 42

    @patch("victorialogs_client.requests.get")
    def test_stats_query_delegates_to_query_logs(self, mock_get):
        """Stats query delegates to query_logs (same /query endpoint)."""
        mock_get.return_value = MagicMock(status_code=200, text="")

        query_stats("* | stats count() as c", 0, 1)

        call_args = mock_get.call_args
        url = call_args[0][0]
        assert "/select/logsql/query" in url

    @patch("victorialogs_client.requests.get")
    def test_failed_stats_returns_empty(self, mock_post):
        """Non-200 stats response should return empty list."""
        mock_post.return_value = MagicMock(status_code=500, text="error")
        result = query_stats("*", 0, 1)
        assert result == []
