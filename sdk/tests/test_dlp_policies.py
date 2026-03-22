"""Tests for DlpPoliciesResource."""

from httpx import Response

from cagent.models import DlpPolicyResponse

SAMPLE_DLP = {
    "id": 1,
    "tenant_id": 1,
    "profile_id": 1,
    "enabled": True,
    "mode": "block",
    "skip_domains": ["internal.corp.com"],
    "custom_patterns": [{"name": "SSN", "regex": r"\d{3}-\d{2}-\d{4}"}],
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}


def test_get_dlp_policy(client, mock_api):
    mock_api.get("/api/v1/dlp-policies").mock(
        return_value=Response(200, json=SAMPLE_DLP)
    )
    dlp = client.dlp.get()
    assert isinstance(dlp, DlpPolicyResponse)
    assert dlp.enabled is True
    assert dlp.mode == "block"
    assert len(dlp.skip_domains) == 1


def test_get_dlp_policy_by_profile(client, mock_api):
    route = mock_api.get("/api/v1/dlp-policies").mock(
        return_value=Response(200, json=SAMPLE_DLP)
    )
    client.dlp.get(profile_id=5)
    request = route.calls[0].request
    assert "profile_id=5" in str(request.url)


def test_update_dlp_policy(client, mock_api):
    updated = {**SAMPLE_DLP, "mode": "log", "enabled": False}
    mock_api.put("/api/v1/dlp-policies").mock(
        return_value=Response(200, json=updated)
    )
    dlp = client.dlp.update(enabled=False, mode="log")
    assert dlp.enabled is False
    assert dlp.mode == "log"


def test_update_dlp_with_custom_patterns(client, mock_api):
    route = mock_api.put("/api/v1/dlp-policies").mock(
        return_value=Response(200, json=SAMPLE_DLP)
    )
    client.dlp.update(
        custom_patterns=[{"name": "SSN", "regex": r"\d{3}-\d{2}-\d{4}"}],
        profile_id=3,
    )
    import json

    body = json.loads(route.calls[0].request.content)
    assert body["custom_patterns"][0]["name"] == "SSN"
    assert "profile_id=3" in str(route.calls[0].request.url)
