"""Tests for ProfilesResource."""

from httpx import Response

from cagent.models import ProfileExportData, ProfileImportResult, SecurityProfile
from tests.conftest import (
    SAMPLE_EXPORT,
    SAMPLE_IMPORT_RESULT,
    SAMPLE_PROFILE,
    SAMPLE_PROFILE_2,
)


def test_list_profiles(client, mock_api):
    mock_api.get("/api/v1/security-profiles").mock(
        return_value=Response(
            200,
            json={
                "items": [SAMPLE_PROFILE, SAMPLE_PROFILE_2],
                "total": 2,
                "limit": 100,
                "offset": 0,
            },
        )
    )
    result = client.profiles.list()
    assert result.total == 2
    assert len(result.items) == 2
    assert isinstance(result.items[0], SecurityProfile)
    assert result.items[0].name == "default"


def test_list_profiles_pagination(client, mock_api):
    mock_api.get("/api/v1/security-profiles").mock(
        return_value=Response(
            200,
            json={"items": [SAMPLE_PROFILE_2], "total": 2, "limit": 1, "offset": 1},
        )
    )
    result = client.profiles.list(limit=1, offset=1)
    assert result.limit == 1
    assert result.offset == 1
    assert result.items[0].name == "research"


def test_get_profile(client, mock_api):
    mock_api.get("/api/v1/security-profiles/1").mock(
        return_value=Response(200, json=SAMPLE_PROFILE)
    )
    profile = client.profiles.get(1)
    assert profile.id == 1
    assert profile.name == "default"
    assert profile.pids_limit == 256


def test_create_profile(client, mock_api):
    mock_api.post("/api/v1/security-profiles").mock(
        return_value=Response(200, json=SAMPLE_PROFILE_2)
    )
    profile = client.profiles.create(name="research", description="Research agent profile")
    assert profile.name == "research"


def test_update_profile(client, mock_api):
    updated = {**SAMPLE_PROFILE, "name": "updated"}
    mock_api.put("/api/v1/security-profiles/1").mock(
        return_value=Response(200, json=updated)
    )
    profile = client.profiles.update(1, name="updated")
    assert profile.name == "updated"


def test_delete_profile(client, mock_api):
    mock_api.delete("/api/v1/security-profiles/2").mock(
        return_value=Response(200, json={"deleted": True, "id": 2})
    )
    result = client.profiles.delete(2)
    assert result["deleted"] is True


def test_export_profile(client, mock_api):
    mock_api.get("/api/v1/security-profiles/1/export").mock(
        return_value=Response(200, json=SAMPLE_EXPORT)
    )
    data = client.profiles.export(1)
    assert isinstance(data, ProfileExportData)
    assert data.name == "default"
    assert len(data.domain_policies) == 1
    assert data.domain_policies[0].domain == "api.openai.com"


def test_import_profile(client, mock_api):
    mock_api.post("/api/v1/security-profiles/1/import").mock(
        return_value=Response(200, json=SAMPLE_IMPORT_RESULT)
    )
    result = client.profiles.import_data(1, SAMPLE_EXPORT)
    assert isinstance(result, ProfileImportResult)
    assert result.domain_policies_created == 1


def test_import_profile_with_model(client, mock_api):
    """import_data accepts both dict and ProfileExportData."""
    mock_api.post("/api/v1/security-profiles/1/import").mock(
        return_value=Response(200, json=SAMPLE_IMPORT_RESULT)
    )
    data = ProfileExportData.model_validate(SAMPLE_EXPORT)
    result = client.profiles.import_data(1, data)
    assert result.profile_id == 1


def test_forward_compat_extra_fields(client, mock_api):
    """Extra fields from API are ignored, not errors."""
    extended = {**SAMPLE_PROFILE, "new_future_field": "value", "another": 42}
    mock_api.get("/api/v1/security-profiles/1").mock(
        return_value=Response(200, json=extended)
    )
    profile = client.profiles.get(1)
    assert profile.name == "default"
