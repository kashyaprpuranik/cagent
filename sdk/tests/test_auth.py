"""Tests for client.me() auth endpoint."""

from httpx import Response

from cagent.models import AuthInfo

SAMPLE_ME = {
    "token_type": "user",
    "cell_id": None,
    "tenant_id": 1,
    "tenant_name": "Acme Corp",
    "tenant_slug": "acme",
    "is_super_admin": False,
    "role": "admin",
    "plan": "starter",
    "onboarding_complete": True,
    "max_agent_tokens": 5,
    "hosting_mode": "managed",
    "multi_user": True,
    "user": {"id": 1, "email": "admin@acme.com", "name": "Admin"},
}


def test_me(client, mock_api):
    mock_api.get("/api/v1/auth/me").mock(
        return_value=Response(200, json=SAMPLE_ME)
    )
    info = client.me()
    assert isinstance(info, AuthInfo)
    assert info.tenant_name == "Acme Corp"
    assert info.plan == "starter"
    assert info.role == "admin"
    assert info.user["email"] == "admin@acme.com"


def test_me_minimal(client, mock_api):
    """Handles minimal response (agent token, no user)."""
    mock_api.get("/api/v1/auth/me").mock(
        return_value=Response(
            200,
            json={
                "token_type": "agent",
                "cell_id": "cell-abc",
                "tenant_id": 1,
                "is_super_admin": False,
                "plan": "free",
            },
        )
    )
    info = client.me()
    assert info.token_type == "agent"
    assert info.cell_id == "cell-abc"
    assert info.user is None
