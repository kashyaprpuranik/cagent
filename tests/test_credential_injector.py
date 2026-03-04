"""
Tests for credential injection logic (now handled by Envoy ext_authz via warden).

These tests verify the domain matching and header formatting logic used
by the ext_authz endpoint for credential injection.

With the MITM proxy enabled, credential injection works for
both HTTP and HTTPS requests. mitmproxy decrypts HTTPS traffic and forwards it
as plain HTTP to Envoy, where ext_authz injects credentials as usual.
"""


class TestDomainMatching:
    """Test domain matching logic used by credential injection."""

    def test_exact_domain_match(self):
        """Should match exact domains."""

        def match_domain(pattern: str, domain: str) -> bool:
            """Match domain against pattern (supports wildcard prefix)."""
            if not pattern:
                return False
            if pattern.startswith("*."):
                suffix = pattern[1:]  # .github.com
                return domain.endswith(suffix) or domain == pattern[2:]
            return domain == pattern

        # Exact matches
        assert match_domain("api.openai.com", "api.openai.com")
        assert match_domain("api.github.com", "api.github.com")

        # Should not match different domains
        assert not match_domain("api.openai.com", "api.anthropic.com")
        assert not match_domain("github.com", "api.github.com")

    def test_wildcard_domain_match(self):
        """Should match wildcard domain patterns."""

        def match_domain(pattern: str, domain: str) -> bool:
            if not pattern:
                return False
            if pattern.startswith("*."):
                suffix = pattern[1:]  # .github.com
                return domain.endswith(suffix) or domain == pattern[2:]
            return domain == pattern

        # Wildcard matches
        assert match_domain("*.github.com", "api.github.com")
        assert match_domain("*.github.com", "raw.github.com")
        assert match_domain("*.github.com", "github.com")

        # Should not match unrelated domains
        assert not match_domain("*.github.com", "githubusercontent.com")
        assert not match_domain("*.github.com", "evil-github.com")

    def test_host_with_port(self):
        """Should strip port from host before matching."""

        def clean_host(host):
            return host.split(":")[0] if ":" in host else host

        assert clean_host("api.github.com:443") == "api.github.com"
        assert clean_host("api.github.com") == "api.github.com"
        assert clean_host("localhost:8080") == "localhost"


class TestHeaderFormatting:
    """Test header value formatting for credential injection."""

    def test_bearer_token_format(self):
        """Should format Bearer token correctly."""

        def format_header(template: str, value: str) -> str:
            return template.replace("{value}", value)

        assert format_header("Bearer {value}", "sk-123") == "Bearer sk-123"
        assert format_header("token {value}", "ghp-abc") == "token ghp-abc"
        assert format_header("{value}", "plain-key") == "plain-key"

    def test_custom_header_format(self):
        """Should handle custom header formats."""

        def format_header(template: str, value: str) -> str:
            return template.replace("{value}", value)

        # API key formats
        assert format_header("ApiKey {value}", "key123") == "ApiKey key123"
        assert format_header("X-Api-Key: {value}", "secret") == "X-Api-Key: secret"


class TestCredentialResponseParsing:
    """Test parsing of control plane API responses."""

    def test_parse_matched_response(self):
        """Should parse successful credential response."""
        import json

        def parse_credential_response(body):
            try:
                data = json.loads(body)
                if data.get("matched"):
                    return {"header_name": data.get("header_name"), "header_value": data.get("header_value")}
            except Exception:
                pass
            return None

        response = '{"matched": true, "header_name": "Authorization", "header_value": "Bearer sk-123"}'
        result = parse_credential_response(response)

        assert result is not None
        assert result["header_name"] == "Authorization"
        assert result["header_value"] == "Bearer sk-123"

    def test_parse_unmatched_response(self):
        """Should return None for unmatched domain."""
        import json

        def parse_credential_response(body):
            try:
                data = json.loads(body)
                if data.get("matched"):
                    return {"header_name": data.get("header_name"), "header_value": data.get("header_value")}
            except Exception:
                pass
            return None

        response = '{"matched": false}'
        result = parse_credential_response(response)
        assert result is None

    def test_parse_invalid_response(self):
        """Should handle invalid JSON gracefully."""
        import json

        def parse_credential_response(body):
            try:
                data = json.loads(body)
                if data.get("matched"):
                    return {"header_name": data.get("header_name"), "header_value": data.get("header_value")}
            except Exception:
                pass
            return None

        result = parse_credential_response("not json")
        assert result is None

        result = parse_credential_response("")
        assert result is None

        result = parse_credential_response(None)
        assert result is None


class TestURLEncoding:
    """Test URL encoding for API queries."""

    def test_url_encode_simple(self):
        """Should encode simple strings correctly."""
        from urllib.parse import quote

        assert quote("api.github.com", safe="") == "api.github.com"
        assert quote("test domain.com", safe="") == "test%20domain.com"

    def test_url_encode_special_chars(self):
        """Should encode special characters."""
        from urllib.parse import quote

        assert quote("domain?test=1", safe="") == "domain%3Ftest%3D1"
        assert quote("domain&other", safe="") == "domain%26other"


