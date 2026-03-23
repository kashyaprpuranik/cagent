"""Shared test fixtures."""

import pytest
import respx

from cagent import CagentClient


@pytest.fixture
def mock_api():
    """respx mock router for the CP API."""
    with respx.mock(base_url="https://app.cagent-control.com") as router:
        yield router


@pytest.fixture
def client(mock_api):
    """CagentClient wired to the respx mock."""
    with CagentClient(api_token="test-token") as c:
        yield c


# -- Sample data --

SAMPLE_PROFILE = {
    "id": 1,
    "tenant_id": 1,
    "name": "default",
    "description": "Default profile",
    "runtime_policy": "hardened",
    "pids_limit": 256,
    "cell_count": 2,
    "policy_count": 5,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}

SAMPLE_PROFILE_2 = {
    **SAMPLE_PROFILE,
    "id": 2,
    "name": "research",
    "description": "Research agent profile",
}

SAMPLE_CELL = {
    "cell_id": "cell-abc",
    "status": "running",
    "online": True,
    "tenant_id": 1,
    "last_heartbeat": "2026-01-01T00:00:00Z",
    "security_profile_name": "default",
}

SAMPLE_CELL_STATUS = {
    "cell_id": "cell-abc",
    "status": "running",
    "container_id": "abc123",
    "uptime_seconds": 3600,
    "cpu_percent": 15,
    "memory_mb": 256,
    "memory_limit_mb": 1024,
    "last_heartbeat": "2026-01-01T00:00:00Z",
    "pending_command": None,
    "last_command": "restart",
    "last_command_result": "success",
    "last_command_at": "2026-01-01T00:00:00Z",
    "online": True,
    "runtime_policy": "hardened",
    "security_profile_id": 1,
    "security_profile_name": "default",
    "public_ip": "1.2.3.4",
}

SAMPLE_EXPORT = {
    "name": "default",
    "description": "Default profile",
    "security": {"runtime_policy": "hardened"},
    "resource_limits": {"pids_limit": 256},
    "domain_policies": [
        {
            "domain": "api.openai.com",
            "alias": "OpenAI",
            "requests_per_minute": 60,
        }
    ],
    "dlp": {"enabled": False, "mode": "log", "skip_domains": [], "custom_patterns": []},
    "email_policies": [],
}

SAMPLE_IMPORT_RESULT = {
    "profile_id": 1,
    "profile_name": "default",
    "domain_policies_created": 1,
    "email_policies_created": 0,
    "dlp_updated": True,
    "profile_updated": True,
}

SAMPLE_MANIFEST = [
    {
        "file": "research-agent.json",
        "name": "research-agent",
        "description": "Academic research",
        "icon": "book-open",
        "domains": 8,
        "tags": ["research", "academic"],
    }
]
