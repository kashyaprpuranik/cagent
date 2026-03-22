"""Tests for DomainPoliciesResource."""

from httpx import Response

from cagent.models import DomainPolicyResponse

SAMPLE_DOMAIN_POLICY = {
    "id": 1,
    "tenant_id": 1,
    "domain": "api.openai.com",
    "alias": "OpenAI",
    "description": "OpenAI API",
    "enabled": True,
    "profile_id": 1,
    "allowed_paths": ["/v1/chat/*"],
    "requests_per_minute": 60,
    "burst_size": 10,
    "timeout": "30s",
    "read_only": False,
    "expires_at": None,
    "has_credential": True,
    "credential_header": "Authorization",
    "credential_format": "Bearer {value}",
    "credential_rotated_at": "2026-01-01T00:00:00Z",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}


def test_list_domain_policies(client, mock_api):
    mock_api.get("/api/v1/domain-policies").mock(
        return_value=Response(
            200,
            json={"items": [SAMPLE_DOMAIN_POLICY], "total": 1, "limit": 100, "offset": 0},
        )
    )
    result = client.domain_policies.list()
    assert result.total == 1
    assert isinstance(result.items[0], DomainPolicyResponse)
    assert result.items[0].domain == "api.openai.com"
    assert result.items[0].has_credential is True


def test_list_domain_policies_by_profile(client, mock_api):
    route = mock_api.get("/api/v1/domain-policies").mock(
        return_value=Response(
            200,
            json={"items": [], "total": 0, "limit": 100, "offset": 0},
        )
    )
    client.domain_policies.list(profile_id=5)
    request = route.calls[0].request
    assert "profile_id=5" in str(request.url)


def test_get_domain_policy(client, mock_api):
    mock_api.get("/api/v1/domain-policies/1").mock(
        return_value=Response(200, json=SAMPLE_DOMAIN_POLICY)
    )
    policy = client.domain_policies.get(1)
    assert policy.domain == "api.openai.com"
    assert policy.allowed_paths == ["/v1/chat/*"]


def test_create_domain_policy(client, mock_api):
    mock_api.post("/api/v1/domain-policies").mock(
        return_value=Response(200, json=SAMPLE_DOMAIN_POLICY)
    )
    policy = client.domain_policies.create(
        domain="api.openai.com",
        alias="OpenAI",
        requests_per_minute=60,
    )
    assert policy.domain == "api.openai.com"


def test_create_domain_policy_with_credential(client, mock_api):
    route = mock_api.post("/api/v1/domain-policies").mock(
        return_value=Response(200, json=SAMPLE_DOMAIN_POLICY)
    )
    client.domain_policies.create(
        domain="api.openai.com",
        credential={"header": "Authorization", "format": "Bearer {value}", "value": "sk-test"},
    )
    import json

    body = json.loads(route.calls[0].request.content)
    assert body["credential"]["value"] == "sk-test"


def test_update_domain_policy(client, mock_api):
    updated = {**SAMPLE_DOMAIN_POLICY, "requests_per_minute": 120}
    mock_api.put("/api/v1/domain-policies/1").mock(
        return_value=Response(200, json=updated)
    )
    policy = client.domain_policies.update(1, requests_per_minute=120)
    assert policy.requests_per_minute == 120


def test_delete_domain_policy(client, mock_api):
    mock_api.delete("/api/v1/domain-policies/1").mock(
        return_value=Response(200, json={"deleted": True, "id": 1})
    )
    result = client.domain_policies.delete(1)
    assert result["deleted"] is True


def test_rotate_credential(client, mock_api):
    route = mock_api.post("/api/v1/domain-policies/1/rotate-credential").mock(
        return_value=Response(200, json=SAMPLE_DOMAIN_POLICY)
    )
    policy = client.domain_policies.rotate_credential(1, value="sk-new-key")
    assert isinstance(policy, DomainPolicyResponse)
    import json

    body = json.loads(route.calls[0].request.content)
    assert body["value"] == "sk-new-key"
    assert body["header"] == "Authorization"
