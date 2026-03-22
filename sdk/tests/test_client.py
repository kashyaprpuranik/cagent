"""Tests for CagentClient core."""

import os

import pytest
from httpx import Response

from cagent import CagentClient, CagentError
from cagent.exceptions import ApiError, AuthenticationError, NotFoundError


def test_client_requires_token():
    """Client raises if no token provided and env var not set."""
    env = os.environ.copy()
    os.environ.pop("CAGENT_API_TOKEN", None)
    try:
        with pytest.raises(CagentError, match="API token required"):
            CagentClient()
    finally:
        os.environ.update(env)


def test_client_uses_env_var(mock_api):
    """Client picks up CAGENT_API_TOKEN from env."""
    os.environ["CAGENT_API_TOKEN"] = "env-token"
    try:
        with CagentClient() as c:
            assert c is not None
    finally:
        del os.environ["CAGENT_API_TOKEN"]


def test_client_context_manager(mock_api):
    """Client works as context manager."""
    with CagentClient(api_token="test") as c:
        assert c.profiles is not None
        assert c.cells is not None


def test_error_401(client, mock_api):
    """401 raises AuthenticationError."""
    mock_api.get("/api/v1/security-profiles").mock(
        return_value=Response(401, json={"detail": "Invalid token"})
    )
    with pytest.raises(AuthenticationError) as exc_info:
        client.profiles.list()
    assert exc_info.value.status_code == 401
    assert "Invalid token" in exc_info.value.detail


def test_error_403(client, mock_api):
    """403 raises AuthenticationError."""
    mock_api.get("/api/v1/security-profiles").mock(
        return_value=Response(403, json={"detail": "Forbidden"})
    )
    with pytest.raises(AuthenticationError) as exc_info:
        client.profiles.list()
    assert exc_info.value.status_code == 403


def test_error_404(client, mock_api):
    """404 raises NotFoundError."""
    mock_api.get("/api/v1/security-profiles/999").mock(
        return_value=Response(404, json={"detail": "Not found"})
    )
    with pytest.raises(NotFoundError) as exc_info:
        client.profiles.get(999)
    assert exc_info.value.status_code == 404


def test_error_500(client, mock_api):
    """500 raises ApiError."""
    mock_api.get("/api/v1/security-profiles").mock(
        return_value=Response(500, text="Internal Server Error")
    )
    with pytest.raises(ApiError) as exc_info:
        client.profiles.list()
    assert exc_info.value.status_code == 500
