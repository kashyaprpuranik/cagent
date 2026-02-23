"""
Tests for the DNS filter (CoreDNS) configuration.
"""

import pytest


class TestCoreDNSConfig:
    """Test CoreDNS configuration validity."""

    def test_corefile_exists(self, configs_dir):
        """Corefile should exist."""
        corefile = configs_dir / "coredns" / "Corefile"
        assert corefile.exists(), f"Corefile not found at {corefile}"

    def test_corefile_has_allowlist(self, configs_dir):
        """Corefile should define allowlisted domains."""
        corefile = configs_dir / "coredns" / "Corefile"
        content = corefile.read_text()

        # Check for key allowed domains
        expected_domains = [
            "github.com",
            "api.github.com",
            "pypi.org",
            "api.openai.com",
            "api.anthropic.com",
        ]

        for domain in expected_domains:
            assert domain in content, f"Expected domain {domain} not in Corefile"

    def test_corefile_blocks_unknown(self, configs_dir):
        """Corefile should block non-allowlisted domains."""
        corefile = configs_dir / "coredns" / "Corefile"
        content = corefile.read_text()

        # Should have a catch-all that returns NXDOMAIN
        assert "NXDOMAIN" in content, "Corefile should return NXDOMAIN for blocked domains"
        assert "template ANY ANY" in content, "Corefile should have catch-all template"

    def test_corefile_has_logging(self, configs_dir):
        """Corefile should log all queries."""
        corefile = configs_dir / "coredns" / "Corefile"
        content = corefile.read_text()

        assert "log" in content.lower(), "Corefile should have logging enabled"


class TestDNSFilterWithContainer:
    """Integration tests for DNS filter using container."""

    @pytest.fixture
    def coredns_container(self, skip_without_docker, configs_dir):
        """Start CoreDNS container for testing."""
        import docker

        client = docker.from_env()

        # Start CoreDNS container
        container = client.containers.run(
            "coredns/coredns:latest",
            command=["-conf", "/Corefile"],
            volumes={str(configs_dir / "coredns" / "Corefile"): {"bind": "/Corefile", "mode": "ro"}},
            detach=True,
            remove=True,
        )

        # Wait for container to be ready
        import time

        time.sleep(2)

        yield container

        # Cleanup
        try:
            container.stop(timeout=5)
        except Exception:
            pass


class TestDNSAllowlist:
    """Test DNS allowlist file parsing."""

    def test_parse_allowlist_domains(self, configs_dir):
        """Should correctly identify allowed domains from Corefile."""
        corefile = configs_dir / "coredns" / "Corefile"
        content = corefile.read_text()

        # Extract domains that have forward directives
        allowed_domains = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            line = line.strip()
            # Domain blocks look like "domain.com {"
            if line.endswith("{") and not line.startswith(".") and not line.startswith("#"):
                domain = line.rstrip(" {").strip()
                if domain and "." in domain:
                    allowed_domains.append(domain)

        # Should have our key domains
        assert "github.com" in allowed_domains
        assert "pypi.org" in allowed_domains
        assert "api.openai.com" in allowed_domains

        # Should NOT have generic catch-all
        assert "." not in allowed_domains or allowed_domains.count(".") <= 1
