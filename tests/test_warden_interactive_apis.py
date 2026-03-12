"""Unit tests for warden connected-mode API endpoints.

Tests the endpoints used by the CP in connected mode:
- /api/commands/* (cell restart, stop, start, wipe)
- /api/metrics (consolidated system metrics, containers, health)
- /api/policies/apply, /api/policies/active
- /api/logs/search
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Mock docker before importing warden modules
mock_docker = MagicMock()
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = mock_docker
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception
mock_docker.containers.list.return_value = []

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


# ---------------------------------------------------------------------------
# Metrics (consolidated endpoint)
# ---------------------------------------------------------------------------
class TestMetricsEndpoint:
    """Test the consolidated /api/metrics endpoint.

    This endpoint returns system metrics, disks, processes, network,
    containers, and health checks in a single response.
    """

    def test_metrics_returns_all_sections(self):
        """GET /api/metrics should return all top-level sections."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}}}
        mock_container.image = MagicMock(tags=["cell:lean"])
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        assert r.status_code == 200
        data = r.json()
        assert "system" in data
        assert "disks" in data
        assert "processes" in data
        assert "network" in data
        assert "containers" in data
        assert "health" in data

    def test_metrics_system_fields(self):
        """GET /api/metrics system section should have expected fields."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}}}
        mock_container.image = MagicMock(tags=["cell:lean"])
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        data = r.json()
        system = data["system"]
        assert "cpu_percent" in system
        assert isinstance(system["cpu_percent"], (int, float))
        assert "cpu_count" in system
        assert system["cpu_count"] >= 1
        assert "memory_mb" in system
        assert system["memory_mb"] > 0
        assert "memory_percent" in system
        assert "disk_used_bytes" in system
        assert "disk_total_bytes" in system
        assert "disk_free_bytes" in system
        assert "load_average" in system
        assert len(system["load_average"]) == 3

    def test_metrics_disks_section(self):
        """GET /api/metrics disks section should list mount points."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}}}
        mock_container.image = MagicMock(tags=["cell:lean"])
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        disks = r.json()["disks"]
        assert isinstance(disks, list)
        assert len(disks) >= 1
        assert "path" in disks[0]
        assert "total_bytes" in disks[0]

    def test_metrics_processes_section(self):
        """GET /api/metrics processes section should list processes."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}}}
        mock_container.image = MagicMock(tags=["cell:lean"])
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        procs = r.json()["processes"]
        assert isinstance(procs, list)
        assert len(procs) >= 1
        assert "pid" in procs[0]
        assert "name" in procs[0]

    def test_metrics_network_section(self):
        """GET /api/metrics network section should list interfaces."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}}}
        mock_container.image = MagicMock(tags=["cell:lean"])
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        network = r.json()["network"]
        assert isinstance(network, list)

    def test_metrics_containers_section(self):
        """GET /api/metrics containers section should list container statuses."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}}}
        mock_container.image = MagicMock(tags=["cell:lean"])
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        containers = r.json()["containers"]
        assert isinstance(containers, list)

    def test_metrics_health_with_oo_healthy(self):
        """GET /api/metrics health section should include OpenObserve check."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z"}}
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        assert r.status_code == 200
        health = r.json()["health"]
        assert "checks" in health
        assert "openobserve" in health["checks"]
        assert health["checks"]["openobserve"]["status"] == "healthy"

    def test_metrics_health_with_oo_unhealthy(self):
        """GET /api/metrics health section should show degraded when OO is down."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z"}}
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.status.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=False),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/metrics")

        assert r.status_code == 200
        health = r.json()["health"]
        assert health["checks"]["openobserve"]["status"] == "unhealthy"
        assert health["status"] == "degraded"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
class TestPolicyEndpoints:
    """Test policy push/query endpoints."""

    def test_get_active_policies(self):
        """GET /api/policies/active should return current policies."""
        mock_config = "domains:\n  - domain: api.openai.com\n  - domain: pypi.org\n"
        with patch("routers.policies.Path") as mock_path:
            mock_path_instance = MagicMock()
            mock_path_instance.read_text.return_value = mock_config
            mock_path.return_value = mock_path_instance
            r = client.get("/api/policies/active")

        assert r.status_code == 200
        data = r.json()
        assert "policies" in data
        assert "count" in data
        assert data["count"] == 2
        domains = [p["domain"] for p in data["policies"]]
        assert "api.openai.com" in domains
        assert "pypi.org" in domains

    def test_apply_policies_updates_config(self):
        """POST /api/policies/apply should update config and regenerate."""
        mock_config = "domains:\n  - domain: old.com\n"
        with (
            patch("routers.policies.Path") as mock_path,
            patch("routers.policies.ConfigGenerator"),
            patch("routers.policies.docker_client"),
        ):
            mock_path_instance = MagicMock()
            mock_path_instance.read_text.return_value = mock_config
            mock_path.return_value = mock_path_instance

            r = client.post(
                "/api/policies/apply",
                json={
                    "policies": [
                        {"domain": "api.github.com"},
                        {"domain": "pypi.org", "allowed_paths": ["/simple/"]},
                        {"domain": "api.openai.com", "requests_per_minute": 100, "burst_size": 20},
                    ]
                },
            )

        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "applied"
        assert data["policy_count"] == 3

    def test_apply_policies_invalid_input(self):
        """POST /api/policies/apply with non-list policies should fail validation."""
        r = client.post("/api/policies/apply", json={"policies": "not-a-list"})
        assert r.status_code == 422

    def test_apply_policies_missing_domain(self):
        """POST /api/policies/apply with missing domain field should fail validation."""
        r = client.post("/api/policies/apply", json={"policies": [{"allowed_paths": ["/"]}]})
        assert r.status_code == 422

    def test_apply_policies_rejects_domain_injection(self):
        """Domains with newlines/braces/special chars should be rejected."""
        for bad_domain in [
            "evil.com\nforward . 8.8.8.8",
            "evil.com}",
            "evil.com{",
            "evil.com; rm -rf /",
            "evil.com\tevil",
            "",
        ]:
            r = client.post("/api/policies/apply", json={"policies": [{"domain": bad_domain}]})
            assert r.status_code == 422, f"Domain {bad_domain!r} was not rejected"

    def test_apply_policies_accepts_valid_domains(self):
        """Valid domain patterns should be accepted."""
        mock_config = "domains: []\n"
        with (
            patch("routers.policies.Path") as mock_path,
            patch("routers.policies.ConfigGenerator"),
            patch("routers.policies.docker_client"),
        ):
            mock_path_instance = MagicMock()
            mock_path_instance.read_text.return_value = mock_config
            mock_path.return_value = mock_path_instance

            r = client.post(
                "/api/policies/apply",
                json={
                    "policies": [
                        {"domain": "api.github.com"},
                        {"domain": "*.openai.com"},
                        {"domain": "my-service_v2.example.com"},
                    ]
                },
            )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Log Search
# ---------------------------------------------------------------------------
class TestLogSearch:
    """Test log search endpoint (OO-backed).

    The search_logs endpoint uses lazy imports:
        from openobserve_client import datetime_to_us, now_us, query_openobserve
    so we must patch at the openobserve_client module level.
    """

    def test_search_logs_returns_hits(self):
        """GET /api/logs/search should return OO query results."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
            patch("openobserve_client.datetime_to_us", return_value=0),
        ):
            mock_query.return_value = [
                {"message": "test log", "source": "envoy", "_timestamp": 123456},
            ]
            r = client.get("/api/logs/search", params={"query": "test", "limit": 10})

        assert r.status_code == 200
        data = r.json()
        assert "hits" in data
        assert len(data["hits"]) == 1
        assert data["hits"][0]["message"] == "test log"

    def test_search_logs_with_source_filter(self):
        """Search with source filter should include WHERE clause."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
        ):
            mock_query.return_value = []
            r = client.get("/api/logs/search", params={"source": "envoy"})

            assert r.status_code == 200
            # Verify the SQL query includes the source filter
            call_args = mock_query.call_args
            sql = call_args[0][0]
            assert "source = 'envoy'" in sql

    def test_search_logs_with_time_range(self):
        """Search with explicit time range should use provided values."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
        ):
            mock_query.return_value = []
            r = client.get(
                "/api/logs/search",
                params={
                    "start": "2026-01-01T00:00:00+00:00",
                    "end": "2026-01-02T00:00:00+00:00",
                },
            )
            assert r.status_code == 200

    def test_search_logs_oo_import_error_returns_empty(self):
        """If openobserve_client is not importable, should return empty results.

        The endpoint catches ImportError (OO client not installed/available)
        and returns empty results gracefully.
        """
        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "openobserve_client":
                raise ImportError("No module named 'openobserve_client'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            # Clear the cached module so the lazy import re-executes
            saved = sys.modules.pop("openobserve_client", None)
            try:
                r = client.get("/api/logs/search", params={"query": "test"})
            finally:
                if saved is not None:
                    sys.modules["openobserve_client"] = saved

        assert r.status_code == 200
        data = r.json()
        assert data["hits"] == []
        assert data["total"] == 0

    def test_search_logs_escapes_sql_injection(self):
        """User input with single quotes should be escaped in SQL."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
        ):
            mock_query.return_value = []
            r = client.get(
                "/api/logs/search",
                params={"query": "'; DROP TABLE default; --", "source": "x'y"},
            )

            assert r.status_code == 200
            sql = mock_query.call_args[0][0]
            # Single quotes must be doubled, not left raw
            assert "''; DROP TABLE" in sql
            assert "source = 'x''y'" in sql


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
class TestCommandEndpoints:
    """Test cell command endpoints."""

    def test_restart_cell(self):
        """POST /api/commands/restart should restart the cell container."""
        mock_container = MagicMock()
        mock_container.name = "cell"

        with patch("routers.commands.discover_cell_containers", return_value=[mock_container]):
            r = client.post("/api/commands/restart")

        assert r.status_code == 200
        data = r.json()
        assert data["command"] == "restart"
        assert data["status"] == "completed"
        mock_container.restart.assert_called_once()

    def test_stop_cell(self):
        """POST /api/commands/stop should stop the cell container."""
        mock_container = MagicMock()
        mock_container.name = "cell"

        with patch("routers.commands.discover_cell_containers", return_value=[mock_container]):
            r = client.post("/api/commands/stop")

        assert r.status_code == 200
        assert r.json()["command"] == "stop"
        mock_container.stop.assert_called_once()

    def test_start_cell(self):
        """POST /api/commands/start should start the cell container."""
        mock_container = MagicMock()
        mock_container.name = "cell"

        with patch("routers.commands.discover_cell_containers", return_value=[mock_container]):
            r = client.post("/api/commands/start")

        assert r.status_code == 200
        assert r.json()["command"] == "start"
        mock_container.start.assert_called_once()

    def test_command_no_cell_returns_404(self):
        """Commands should return 404 when no cell container exists."""
        with patch("routers.commands.discover_cell_containers", return_value=[]):
            r = client.post("/api/commands/restart")

        assert r.status_code == 404
        assert "No cell" in r.json()["detail"]
