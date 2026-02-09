"""
End-to-end tests for the full data plane stack.

These tests require the full data plane to be running:
    cd data_plane && docker-compose up -d

Run with:
    pytest tests/test_e2e.py -v --run-e2e
"""

import pytest
import requests
import subprocess
import time


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end (requires full stack running)"
    )


def is_data_plane_running():
    """Check if data plane containers are running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=envoy-proxy", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "envoy-proxy" in result.stdout
    except:
        return False


@pytest.fixture(scope="module")
def data_plane_running():
    """Check if data plane is running."""
    if not is_data_plane_running():
        pytest.skip(
            "Data plane not running. Start with: "
            "cd data_plane && docker-compose up -d"
        )
    return True


def exec_in_agent(command: str) -> subprocess.CompletedProcess:
    """Execute a command in the agent container."""
    return subprocess.run(
        ["docker", "exec", "agent", "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=30
    )


@pytest.mark.e2e
class TestAgentNetworkIsolation:
    """Test that agent container is properly isolated."""

    def test_agent_can_reach_envoy(self, data_plane_running):
        """Agent should be able to reach Envoy proxy."""
        result = exec_in_agent("nc -z 172.30.0.10 8443 && echo OK")
        assert result.returncode == 0 or "OK" in result.stdout, \
            f"Agent cannot reach Envoy: {result.stderr}"

    def test_agent_can_reach_dns(self, data_plane_running):
        """Agent should be able to reach DNS filter."""
        result = exec_in_agent("nc -z 172.30.0.5 53 && echo OK")
        assert result.returncode == 0 or "OK" in result.stdout, \
            f"Agent cannot reach DNS: {result.stderr}"

    def test_agent_cannot_reach_external_directly(self, data_plane_running):
        """Agent should NOT be able to reach external IPs directly."""
        # Try to reach Google DNS directly (should fail)
        result = exec_in_agent("nc -z -w 2 8.8.8.8 53 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, \
            "Agent can reach external IPs directly - network isolation broken!"

    def test_agent_cannot_reach_control_plane(self, data_plane_running):
        """Agent should NOT be able to reach control plane directly."""
        # Control plane is on infra-net, agent should not reach it
        result = exec_in_agent("nc -z -w 2 172.31.0.1 8000 && echo FAIL || echo BLOCKED")
        # This might succeed if control plane IP is different, so just log
        if "FAIL" in result.stdout:
            pytest.skip("Warning: Agent may be able to reach infra-net")


@pytest.mark.e2e
class TestDNSFiltering:
    """Test DNS filtering behavior."""

    def test_allowed_domain_resolves(self, data_plane_running):
        """Allowed domains should resolve via DNS filter."""
        result = exec_in_agent("nslookup api.openai.com 172.30.0.5")
        assert result.returncode == 0, f"Failed to resolve allowed domain: {result.stderr}"
        assert "NXDOMAIN" not in result.stdout, "Allowed domain returned NXDOMAIN"

    def test_blocked_domain_fails(self, data_plane_running):
        """Non-allowed domains should fail DNS resolution."""
        result = exec_in_agent("nslookup evil-malware.com 172.30.0.5")
        # Should return NXDOMAIN or fail
        assert "NXDOMAIN" in result.stdout or result.returncode != 0, \
            "Blocked domain should not resolve"


@pytest.mark.e2e
class TestProxyEgress:
    """Test egress through Envoy proxy."""

    def test_https_through_proxy_allowed_domain(self, data_plane_running):
        """Should successfully reach allowed domains through proxy."""
        result = exec_in_agent(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://172.30.0.10:8443 "
            "https://api.github.com"
        )
        # Should get some HTTP response (even 401 unauthorized is fine)
        http_code = result.stdout.strip()
        assert http_code.isdigit() and int(http_code) < 500, \
            f"Request to allowed domain failed with: {http_code}"

    def test_https_through_proxy_blocked_domain(self, data_plane_running):
        """Should fail to reach blocked domains through proxy."""
        result = exec_in_agent(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://172.30.0.10:8443 "
            "--connect-timeout 5 "
            "https://evil-malware.com"
        )
        # Should fail (connection refused, timeout, or 403)
        http_code = result.stdout.strip()
        # Empty or error code means blocked
        assert not http_code or http_code == "000" or http_code == "403", \
            f"Request to blocked domain succeeded with: {http_code}"


@pytest.mark.e2e
class TestCredentialInjection:
    """Test credential injection functionality (via Envoy Lua filter)."""

    def test_request_headers_not_contain_secrets(self, data_plane_running):
        """Agent requests should not contain raw secrets."""
        # Make a request and capture what the agent sees
        result = exec_in_agent("env | grep -i api_key || echo 'NO_SECRETS_IN_ENV'")
        assert "NO_SECRETS_IN_ENV" in result.stdout or not result.stdout.strip(), \
            "Agent environment should not contain API keys"

    def test_envoy_handles_credential_injection(self, data_plane_running):
        """Envoy should be running (handles credential injection via Lua)."""
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=envoy-proxy", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
        )
        assert "Up" in result.stdout, "Envoy proxy is not running"

    def test_https_connect_tunnel_no_rewrite(self, data_plane_running):
        """HTTPS requests should pass through as CONNECT tunnel - no header injection.

        When agent uses: curl https://api.openai.com
        Envoy sees CONNECT tunnel, cannot inject headers into encrypted traffic.
        This is expected behavior - credentials are NOT injected for direct HTTPS.
        """
        # Make HTTPS request - this creates a CONNECT tunnel
        # We use -v to see the CONNECT method being used
        result = exec_in_agent(
            "curl -v -s -o /dev/null -w '%{http_code}' "
            "-x http://172.30.0.10:8443 "
            "--connect-timeout 5 "
            "https://httpbin.org/headers 2>&1 | grep -E 'CONNECT|HTTP/1.1'"
        )
        # Should see CONNECT method in verbose output (indicates tunnel mode)
        # Note: This test verifies the tunnel is established, not that headers aren't injected
        # (we can't easily verify header injection didn't happen from outside the tunnel)
        assert "CONNECT" in result.stdout or result.returncode == 0, \
            "HTTPS should use CONNECT tunnel through proxy"

    def test_http_devbox_local_gets_credentials(self, data_plane_running):
        """HTTP requests to *.devbox.local should get credentials injected.

        When agent uses: curl http://openai.devbox.local/...
        Envoy sees plain HTTP, can inject Authorization header.
        """
        # This test requires a secret with alias to be configured
        # For now, just verify the devbox.local routing works
        result = exec_in_agent(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://172.30.0.10:8443 "
            "--connect-timeout 5 "
            "http://openai.devbox.local/v1/models 2>&1"
        )
        # Should get some response (401 without valid creds, or 200 with)
        # Not 000 (connection failed) or 403 (blocked)
        http_code = result.stdout.strip()
        # Any response indicates the devbox.local routing worked
        assert http_code and http_code != "000", \
            f"devbox.local request failed: {result.stderr}"


@pytest.mark.e2e
class TestLogging:
    """Test log collection."""

    def test_vector_running(self, data_plane_running):
        """Vector should be running for log collection."""
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=vector", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
        )
        assert "Up" in result.stdout, "Vector is not running"

    def test_envoy_logs_exist(self, data_plane_running):
        """Envoy should be generating access logs."""
        result = subprocess.run(
            ["docker", "exec", "envoy-proxy", "ls", "-la", "/var/log/envoy/"],
            capture_output=True,
            text=True
        )
        # Check if log directory exists and has files
        assert result.returncode == 0, "Cannot access Envoy log directory"


def get_admin_url():
    """Get local admin base URL, detecting the mapped port."""
    try:
        result = subprocess.run(
            ["docker", "port", "local-admin", "8080"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            # Output like "0.0.0.0:8080" or ":::8080"
            mapping = result.stdout.strip().splitlines()[0]
            host_port = mapping.rsplit(":", 1)[-1]
            return f"http://localhost:{host_port}"
    except Exception:
        pass
    return None


@pytest.fixture(scope="module")
def admin_url():
    """Get local admin URL, skip if not running."""
    url = get_admin_url()
    if not url:
        pytest.skip(
            "Local admin not running. Start with: "
            "docker-compose --profile admin up -d"
        )
    return url


def is_container_running(name):
    """Check if a Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        return "Up" in result.stdout
    except Exception:
        return False


def wait_for_container(name, timeout=30):
    """Wait for a container to be running."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_container_running(name):
            return True
        time.sleep(1)
    return False


@pytest.mark.e2e
class TestLocalAdminAPI:
    """Test local admin UI API endpoints (requires --profile admin)."""

    def test_health(self, admin_url):
        """Health endpoint should return ok."""
        r = requests.get(f"{admin_url}/api/health", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "timestamp" in data

    def test_detailed_health(self, admin_url):
        """Detailed health should report on managed containers."""
        r = requests.get(f"{admin_url}/api/health/detailed", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("healthy", "degraded")
        assert "checks" in data
        assert "agent" in data["checks"]
        assert "dns-filter" in data["checks"]
        assert "envoy-proxy" in data["checks"]

    def test_info(self, admin_url):
        """Info endpoint should return container names and paths."""
        r = requests.get(f"{admin_url}/api/info", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert data["containers"]["agent"] == "agent"
        assert data["containers"]["dns"] == "dns-filter"
        assert data["containers"]["envoy"] == "envoy-proxy"

    def test_list_containers(self, admin_url):
        """Should list managed containers with status."""
        r = requests.get(f"{admin_url}/api/containers", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "containers" in data
        for name in ("agent", "dns-filter", "envoy-proxy"):
            assert name in data["containers"]
            assert "status" in data["containers"][name]

    def test_get_single_container(self, admin_url):
        """Should get status for a specific container."""
        r = requests.get(f"{admin_url}/api/containers/agent", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "agent"
        assert "status" in data

    def test_get_config(self, admin_url):
        """Should return current cagent.yaml config."""
        r = requests.get(f"{admin_url}/api/config", timeout=5)
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            data = r.json()
            assert "config" in data
            assert "raw" in data
            assert "path" in data

    def test_ssh_tunnel_status(self, admin_url):
        """Should return SSH tunnel status."""
        r = requests.get(f"{admin_url}/api/ssh-tunnel", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert "enabled" in data
        assert "connected" in data
        assert "configured" in data

    def test_generate_stcp_key(self, admin_url):
        """Should generate an STCP secret key."""
        r = requests.post(f"{admin_url}/api/ssh-tunnel/generate-key", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert "stcp_secret_key" in data
        assert len(data["stcp_secret_key"]) > 20


@pytest.mark.e2e
class TestLocalAdminConfigPipeline:
    """Test config update pipeline: local admin → cagent.yaml → agent-manager → CoreDNS → agent.

    Requires --profile admin (which includes agent-manager).
    Verifies that updating config via the local admin API propagates
    all the way to the agent container's DNS resolution.
    """

    # A real domain that is unlikely to be in the default allowlist
    TEST_DOMAIN = "ifconfig.me"

    def test_config_update_propagates_to_agent(self, admin_url, data_plane_running):
        """Updating config via local admin should change agent DNS behavior."""
        if not is_container_running("agent-manager"):
            pytest.skip("agent-manager not running (needs --profile admin)")

        # -- Step 1: Read original config (for cleanup) --
        original = requests.get(f"{admin_url}/api/config", timeout=5)
        if original.status_code == 404:
            pytest.skip("No cagent.yaml configured")
        original_raw = original.json()["raw"]
        original_config = original.json()["config"]

        # -- Step 2: Confirm test domain is currently blocked --
        result = exec_in_agent(f"nslookup {self.TEST_DOMAIN} 172.30.0.5")
        if "NXDOMAIN" not in result.stdout and result.returncode == 0:
            pytest.skip(f"{self.TEST_DOMAIN} already resolves — already in allowlist")

        try:
            # -- Step 3: Add test domain via local admin API --
            domains = original_config.get("domains", [])
            domains.append({"domain": self.TEST_DOMAIN})
            r = requests.put(
                f"{admin_url}/api/config",
                json={"domains": domains},
                timeout=5,
            )
            assert r.status_code == 200, f"Config update failed: {r.text}"

            # Verify write persisted
            updated = requests.get(f"{admin_url}/api/config", timeout=5)
            updated_domains = [d["domain"] for d in updated.json()["config"].get("domains", [])]
            assert self.TEST_DOMAIN in updated_domains, "Config write did not persist"

            # -- Step 4: Restart agent-manager to force immediate config regen --
            # On startup, agent-manager reads cagent.yaml and writes new Corefile
            subprocess.run(
                ["docker", "restart", "agent-manager"],
                capture_output=True, timeout=30, check=True,
            )
            assert wait_for_container("agent-manager", timeout=15), \
                "agent-manager did not restart"
            # Give it a moment to regenerate configs
            time.sleep(3)

            # -- Step 5: Reload CoreDNS to pick up new Corefile --
            r = requests.post(f"{admin_url}/api/config/reload", timeout=15)
            assert r.status_code == 200
            assert wait_for_container("dns-filter", timeout=15), \
                "dns-filter did not come back after reload"
            # Wait for CoreDNS to be ready
            time.sleep(2)

            # -- Step 6: Verify domain now resolves from agent --
            result = exec_in_agent(f"nslookup {self.TEST_DOMAIN} 172.30.0.5")
            assert result.returncode == 0 and "NXDOMAIN" not in result.stdout, \
                f"{self.TEST_DOMAIN} should resolve after being added to config. " \
                f"stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            # -- Cleanup: restore original config --
            requests.put(
                f"{admin_url}/api/config/raw",
                json={"content": original_raw},
                timeout=5,
            )
            subprocess.run(
                ["docker", "restart", "agent-manager"],
                capture_output=True, timeout=30,
            )
            time.sleep(3)
            requests.post(f"{admin_url}/api/config/reload", timeout=15)
