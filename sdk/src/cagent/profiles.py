"""Security profile management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import httpx

from cagent.exceptions import CagentError
from cagent.models import (
    CommunityProfile,
    PaginatedResponse,
    ProfileExportData,
    ProfileImportResult,
    SecurityProfile,
)

if TYPE_CHECKING:
    from cagent.client import CagentClient

COMMUNITY_BASE_URL = (
    "https://raw.githubusercontent.com/kashyaprpuranik/cagent/main/configs/profiles"
)
MANIFEST_URL = f"{COMMUNITY_BASE_URL}/manifest.json"


class ProfilesResource:
    """Manages security profiles via the CP API."""

    def __init__(self, client: CagentClient) -> None:
        self._client = client

    def list(
        self, limit: int = 100, offset: int = 0
    ) -> PaginatedResponse[SecurityProfile]:
        """List security profiles."""
        resp = self._client.request(
            "GET",
            "/api/v1/security-profiles",
            params={"limit": limit, "offset": offset},
        )
        data = resp.json()
        return PaginatedResponse[SecurityProfile](
            items=[SecurityProfile.model_validate(p) for p in data["items"]],
            total=data["total"],
            limit=data["limit"],
            offset=data["offset"],
        )

    def get(self, profile_id: int) -> SecurityProfile:
        """Get a single security profile."""
        resp = self._client.request(
            "GET", f"/api/v1/security-profiles/{profile_id}"
        )
        return SecurityProfile.model_validate(resp.json())

    def create(
        self,
        name: str,
        description: Optional[str] = None,
        runtime_policy: Optional[str] = None,
        pids_limit: Optional[int] = None,
    ) -> SecurityProfile:
        """Create a new security profile."""
        body: dict = {"name": name}
        if description is not None:
            body["description"] = description
        if runtime_policy is not None:
            body["runtime_policy"] = runtime_policy
        if pids_limit is not None:
            body["pids_limit"] = pids_limit
        resp = self._client.request(
            "POST", "/api/v1/security-profiles", json=body
        )
        return SecurityProfile.model_validate(resp.json())

    def update(
        self,
        profile_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        runtime_policy: Optional[str] = None,
        pids_limit: Optional[int] = None,
    ) -> SecurityProfile:
        """Update a security profile."""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if runtime_policy is not None:
            body["runtime_policy"] = runtime_policy
        if pids_limit is not None:
            body["pids_limit"] = pids_limit
        resp = self._client.request(
            "PUT", f"/api/v1/security-profiles/{profile_id}", json=body
        )
        return SecurityProfile.model_validate(resp.json())

    def delete(self, profile_id: int) -> dict:
        """Delete a security profile."""
        resp = self._client.request(
            "DELETE", f"/api/v1/security-profiles/{profile_id}"
        )
        return resp.json()

    def export(self, profile_id: int) -> ProfileExportData:
        """Export a profile's full configuration (no credentials)."""
        resp = self._client.request(
            "GET", f"/api/v1/security-profiles/{profile_id}/export"
        )
        return ProfileExportData.model_validate(resp.json())

    def import_data(
        self, profile_id: int, data: ProfileExportData | dict
    ) -> ProfileImportResult:
        """Import a profile configuration (replaces all policies)."""
        if isinstance(data, ProfileExportData):
            body = data.model_dump()
        else:
            body = data
        resp = self._client.request(
            "POST", f"/api/v1/security-profiles/{profile_id}/import", json=body
        )
        return ProfileImportResult.model_validate(resp.json())

    # -- Community profiles --

    def list_community(self) -> list[CommunityProfile]:
        """Fetch the community profiles manifest from GitHub."""
        resp = httpx.get(MANIFEST_URL, timeout=15.0)
        resp.raise_for_status()
        return [CommunityProfile.model_validate(p) for p in resp.json()]

    def apply(
        self, name: str, profile_id: Optional[int] = None
    ) -> ProfileImportResult:
        """Apply a community profile by name.

        Fetches the profile JSON from GitHub and imports it into the
        specified profile (or the default profile if not specified).

        Args:
            name: Community profile name (e.g. "research-agent").
            profile_id: Target profile ID. If None, uses the default profile.
        """
        url = f"{COMMUNITY_BASE_URL}/{name}.json"
        resp = httpx.get(url, timeout=15.0)
        resp.raise_for_status()
        export_data = ProfileExportData.model_validate(resp.json())
        target_id = profile_id or self._resolve_default_profile_id()
        return self.import_data(target_id, export_data)

    def apply_url(
        self, url: str, profile_id: Optional[int] = None
    ) -> ProfileImportResult:
        """Apply a profile from any URL.

        Fetches the profile JSON from the URL and imports it.

        Args:
            url: URL to a profile JSON file.
            profile_id: Target profile ID. If None, uses the default profile.
        """
        resp = httpx.get(url, timeout=15.0)
        resp.raise_for_status()
        export_data = ProfileExportData.model_validate(resp.json())
        target_id = profile_id or self._resolve_default_profile_id()
        return self.import_data(target_id, export_data)

    def _resolve_default_profile_id(self) -> int:
        """Find the default profile or fall back to the first profile."""
        profiles = self.list(limit=100)
        for p in profiles.items:
            if p.name == "default":
                return p.id
        if profiles.items:
            return profiles.items[0].id
        raise CagentError("No profiles found. Create one first.")
