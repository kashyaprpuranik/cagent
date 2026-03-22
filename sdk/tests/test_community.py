"""Tests for community profile fetching and applying."""

import respx
from httpx import Response

from cagent.models import CommunityProfile
from cagent.profiles import COMMUNITY_BASE_URL, MANIFEST_URL
from tests.conftest import (
    SAMPLE_EXPORT,
    SAMPLE_IMPORT_RESULT,
    SAMPLE_MANIFEST,
    SAMPLE_PROFILE,
)


def test_list_community(client, mock_api):
    """list_community fetches the manifest from GitHub."""
    with respx.mock:
        respx.get(MANIFEST_URL).mock(
            return_value=Response(200, json=SAMPLE_MANIFEST)
        )
        profiles = client.profiles.list_community()

    assert len(profiles) == 1
    assert isinstance(profiles[0], CommunityProfile)
    assert profiles[0].name == "research-agent"
    assert profiles[0].domains == 8


def test_apply_community_profile(client, mock_api):
    """apply() fetches profile JSON from GitHub, then imports it."""
    profile_url = f"{COMMUNITY_BASE_URL}/research-agent.json"

    # Mock the GitHub fetch (outside respx base_url mock)
    with respx.mock:
        # Re-register the CP API mocks inside this context
        respx.get(
            "https://app.cagent-control.com/api/v1/security-profiles",
            params__contains={"limit": "100"},
        ).mock(
            return_value=Response(
                200,
                json={
                    "items": [SAMPLE_PROFILE],
                    "total": 1,
                    "limit": 100,
                    "offset": 0,
                },
            )
        )
        respx.post(
            "https://app.cagent-control.com/api/v1/security-profiles/1/import"
        ).mock(return_value=Response(200, json=SAMPLE_IMPORT_RESULT))
        respx.get(profile_url).mock(
            return_value=Response(200, json=SAMPLE_EXPORT)
        )

        result = client.profiles.apply("research-agent")

    assert result.profile_id == 1
    assert result.domain_policies_created == 1


def test_apply_with_explicit_profile_id(client, mock_api):
    """apply() with explicit profile_id skips default resolution."""
    profile_url = f"{COMMUNITY_BASE_URL}/devops.json"

    with respx.mock:
        respx.get(profile_url).mock(
            return_value=Response(200, json=SAMPLE_EXPORT)
        )
        respx.post(
            "https://app.cagent-control.com/api/v1/security-profiles/5/import"
        ).mock(return_value=Response(200, json={**SAMPLE_IMPORT_RESULT, "profile_id": 5}))

        result = client.profiles.apply("devops", profile_id=5)

    assert result.profile_id == 5


def test_apply_url(client, mock_api):
    """apply_url() fetches from any URL and imports."""
    custom_url = "https://example.com/my-profile.json"

    with respx.mock:
        respx.get(custom_url).mock(
            return_value=Response(200, json=SAMPLE_EXPORT)
        )
        respx.get(
            "https://app.cagent-control.com/api/v1/security-profiles",
            params__contains={"limit": "100"},
        ).mock(
            return_value=Response(
                200,
                json={
                    "items": [SAMPLE_PROFILE],
                    "total": 1,
                    "limit": 100,
                    "offset": 0,
                },
            )
        )
        respx.post(
            "https://app.cagent-control.com/api/v1/security-profiles/1/import"
        ).mock(return_value=Response(200, json=SAMPLE_IMPORT_RESULT))

        result = client.profiles.apply_url(custom_url)

    assert result.profile_id == 1
