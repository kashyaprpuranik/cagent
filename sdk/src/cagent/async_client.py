"""Asynchronous Cagent client."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from cagent.auth import auth_headers, resolve_token
from cagent.client import _extract_detail
from cagent.exceptions import ApiError, AuthenticationError, CagentError, NotFoundError
from cagent.models import (
    AuditEntry,
    AuthInfo,
    Cell,
    CellStatus,
    CommunityProfile,
    DlpPolicyResponse,
    DomainPolicyResponse,
    PaginatedResponse,
    ProfileExportData,
    ProfileImportResult,
    SecurityProfile,
)
from cagent.profiles import COMMUNITY_BASE_URL, MANIFEST_URL


class AsyncCagentClient:
    """Asynchronous client for the Cagent Control Plane API.

    Usage::

        from cagent.async_client import AsyncCagentClient

        async with AsyncCagentClient(api_token="cag_...") as client:
            profiles = await client.profiles.list()
    """

    def __init__(
        self,
        base_url: str = "https://app.cagent-control.com",
        api_token: str | None = None,
        timeout: float = 30.0,
        httpx_client: httpx.AsyncClient | None = None,
    ):
        token = resolve_token(api_token)
        self._base_url = base_url.rstrip("/")
        self._client = httpx_client or httpx.AsyncClient(
            base_url=self._base_url,
            timeout=timeout,
            headers=auth_headers(token),
        )
        self.profiles = AsyncProfilesResource(self)
        self.cells = AsyncCellsResource(self)
        self.domain_policies = AsyncDomainPoliciesResource(self)
        self.dlp = AsyncDlpPoliciesResource(self)
        self.logs = AsyncLogsResource(self)

    async def me(self) -> AuthInfo:
        """Get current user/token info (GET /api/v1/auth/me)."""
        resp = await self.request("GET", "/api/v1/auth/me")
        return AuthInfo.model_validate(resp.json())

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Make an authenticated request with error handling."""
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code in (401, 403):
            detail = _extract_detail(resp)
            raise AuthenticationError(resp.status_code, detail, resp)
        if resp.status_code == 404:
            detail = _extract_detail(resp)
            raise NotFoundError(resp.status_code, detail, resp)
        if resp.status_code >= 400:
            detail = _extract_detail(resp)
            raise ApiError(resp.status_code, detail, resp)
        return resp

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncCagentClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class AsyncProfilesResource:
    """Async security profile management."""

    def __init__(self, client: AsyncCagentClient) -> None:
        self._client = client

    async def list(
        self, limit: int = 100, offset: int = 0
    ) -> PaginatedResponse[SecurityProfile]:
        resp = await self._client.request(
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

    async def get(self, profile_id: int) -> SecurityProfile:
        resp = await self._client.request(
            "GET", f"/api/v1/security-profiles/{profile_id}"
        )
        return SecurityProfile.model_validate(resp.json())

    async def create(
        self,
        name: str,
        description: Optional[str] = None,
        runtime_policy: Optional[str] = None,
        pids_limit: Optional[int] = None,
    ) -> SecurityProfile:
        body: dict = {"name": name}
        if description is not None:
            body["description"] = description
        if runtime_policy is not None:
            body["runtime_policy"] = runtime_policy
        if pids_limit is not None:
            body["pids_limit"] = pids_limit
        resp = await self._client.request(
            "POST", "/api/v1/security-profiles", json=body
        )
        return SecurityProfile.model_validate(resp.json())

    async def update(
        self,
        profile_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        runtime_policy: Optional[str] = None,
        pids_limit: Optional[int] = None,
    ) -> SecurityProfile:
        body: dict = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if runtime_policy is not None:
            body["runtime_policy"] = runtime_policy
        if pids_limit is not None:
            body["pids_limit"] = pids_limit
        resp = await self._client.request(
            "PUT", f"/api/v1/security-profiles/{profile_id}", json=body
        )
        return SecurityProfile.model_validate(resp.json())

    async def delete(self, profile_id: int) -> dict:
        resp = await self._client.request(
            "DELETE", f"/api/v1/security-profiles/{profile_id}"
        )
        return resp.json()

    async def export(self, profile_id: int) -> ProfileExportData:
        resp = await self._client.request(
            "GET", f"/api/v1/security-profiles/{profile_id}/export"
        )
        return ProfileExportData.model_validate(resp.json())

    async def import_data(
        self, profile_id: int, data: ProfileExportData | dict
    ) -> ProfileImportResult:
        if isinstance(data, ProfileExportData):
            body = data.model_dump()
        else:
            body = data
        resp = await self._client.request(
            "POST", f"/api/v1/security-profiles/{profile_id}/import", json=body
        )
        return ProfileImportResult.model_validate(resp.json())

    async def list_community(self) -> list[CommunityProfile]:
        async with httpx.AsyncClient() as http:
            resp = await http.get(MANIFEST_URL, timeout=15.0)
            resp.raise_for_status()
            return [CommunityProfile.model_validate(p) for p in resp.json()]

    async def apply(
        self, name: str, profile_id: Optional[int] = None
    ) -> ProfileImportResult:
        url = f"{COMMUNITY_BASE_URL}/{name}.json"
        async with httpx.AsyncClient() as http:
            resp = await http.get(url, timeout=15.0)
            resp.raise_for_status()
        export_data = ProfileExportData.model_validate(resp.json())
        target_id = profile_id or await self._resolve_default_profile_id()
        return await self.import_data(target_id, export_data)

    async def apply_url(
        self, url: str, profile_id: Optional[int] = None
    ) -> ProfileImportResult:
        async with httpx.AsyncClient() as http:
            resp = await http.get(url, timeout=15.0)
            resp.raise_for_status()
        export_data = ProfileExportData.model_validate(resp.json())
        target_id = profile_id or await self._resolve_default_profile_id()
        return await self.import_data(target_id, export_data)

    async def _resolve_default_profile_id(self) -> int:
        profiles = await self.list(limit=100)
        for p in profiles.items:
            if p.name == "default":
                return p.id
        if profiles.items:
            return profiles.items[0].id
        raise CagentError("No profiles found. Create one first.")


class AsyncCellsResource:
    """Async cell management."""

    def __init__(self, client: AsyncCagentClient) -> None:
        self._client = client

    async def list(
        self, limit: int = 100, offset: int = 0
    ) -> PaginatedResponse[Cell]:
        resp = await self._client.request(
            "GET", "/api/v1/cells", params={"limit": limit, "offset": offset}
        )
        data = resp.json()
        return PaginatedResponse[Cell](
            items=[Cell.model_validate(c) for c in data["items"]],
            total=data["total"],
            limit=data["limit"],
            offset=data["offset"],
        )

    async def get(self, cell_id: str) -> CellStatus:
        resp = await self._client.request(
            "GET", f"/api/v1/cells/{cell_id}/status"
        )
        return CellStatus.model_validate(resp.json())

    async def wipe(self, cell_id: str, workspace: bool = False) -> dict:
        resp = await self._client.request(
            "POST",
            f"/api/v1/cells/{cell_id}/wipe",
            json={"wipe_workspace": workspace},
        )
        return resp.json()

    async def restart(self, cell_id: str) -> dict:
        resp = await self._client.request(
            "POST", f"/api/v1/cells/{cell_id}/restart"
        )
        return resp.json()

    async def stop(self, cell_id: str) -> dict:
        resp = await self._client.request(
            "POST", f"/api/v1/cells/{cell_id}/stop"
        )
        return resp.json()

    async def start(self, cell_id: str) -> dict:
        resp = await self._client.request(
            "POST", f"/api/v1/cells/{cell_id}/start"
        )
        return resp.json()

    async def assign_profile(self, cell_id: str, profile_id: int) -> dict:
        resp = await self._client.request(
            "PUT",
            f"/api/v1/cells/{cell_id}/profile",
            json={"profile_id": profile_id},
        )
        return resp.json()

    async def unassign_profile(self, cell_id: str) -> dict:
        resp = await self._client.request(
            "DELETE", f"/api/v1/cells/{cell_id}/profile"
        )
        return resp.json()


class AsyncDomainPoliciesResource:
    """Async domain policy management."""

    def __init__(self, client: AsyncCagentClient) -> None:
        self._client = client

    async def list(
        self, profile_id: Optional[int] = None, limit: int = 100, offset: int = 0
    ) -> PaginatedResponse[DomainPolicyResponse]:
        params: dict = {"limit": limit, "offset": offset}
        if profile_id is not None:
            params["profile_id"] = profile_id
        resp = await self._client.request("GET", "/api/v1/domain-policies", params=params)
        data = resp.json()
        return PaginatedResponse[DomainPolicyResponse](
            items=[DomainPolicyResponse.model_validate(p) for p in data["items"]],
            total=data["total"],
            limit=data["limit"],
            offset=data["offset"],
        )

    async def get(self, policy_id: int) -> DomainPolicyResponse:
        resp = await self._client.request("GET", f"/api/v1/domain-policies/{policy_id}")
        return DomainPolicyResponse.model_validate(resp.json())

    async def create(self, domain: str, **kwargs: Any) -> DomainPolicyResponse:
        body: dict = {"domain": domain, **{k: v for k, v in kwargs.items() if v is not None}}
        resp = await self._client.request("POST", "/api/v1/domain-policies", json=body)
        return DomainPolicyResponse.model_validate(resp.json())

    async def update(self, policy_id: int, **kwargs: Any) -> DomainPolicyResponse:
        body = {k: v for k, v in kwargs.items() if v is not None}
        resp = await self._client.request("PUT", f"/api/v1/domain-policies/{policy_id}", json=body)
        return DomainPolicyResponse.model_validate(resp.json())

    async def delete(self, policy_id: int) -> dict:
        resp = await self._client.request("DELETE", f"/api/v1/domain-policies/{policy_id}")
        return resp.json()

    async def rotate_credential(
        self, policy_id: int, value: str, header: str = "Authorization", format: str = "Bearer {value}"
    ) -> DomainPolicyResponse:
        body = {"header": header, "format": format, "value": value}
        resp = await self._client.request(
            "POST", f"/api/v1/domain-policies/{policy_id}/rotate-credential", json=body
        )
        return DomainPolicyResponse.model_validate(resp.json())


class AsyncDlpPoliciesResource:
    """Async DLP policy management."""

    def __init__(self, client: AsyncCagentClient) -> None:
        self._client = client

    async def get(self, profile_id: Optional[int] = None) -> DlpPolicyResponse:
        params: dict = {}
        if profile_id is not None:
            params["profile_id"] = profile_id
        resp = await self._client.request("GET", "/api/v1/dlp-policies", params=params)
        return DlpPolicyResponse.model_validate(resp.json())

    async def update(self, profile_id: Optional[int] = None, **kwargs: Any) -> DlpPolicyResponse:
        body = {k: v for k, v in kwargs.items() if v is not None}
        params: dict = {}
        if profile_id is not None:
            params["profile_id"] = profile_id
        resp = await self._client.request("PUT", "/api/v1/dlp-policies", json=body, params=params)
        return DlpPolicyResponse.model_validate(resp.json())


class AsyncLogsResource:
    """Async log query and audit trail."""

    def __init__(self, client: AsyncCagentClient) -> None:
        self._client = client

    async def query(
        self,
        query: str = "",
        source: Optional[str] = None,
        cell_id: Optional[str] = None,
        limit: int = 100,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> list[dict]:
        params: dict = {"query": query, "limit": limit}
        if source is not None:
            params["source"] = source
        if cell_id is not None:
            params["cell_id"] = cell_id
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        resp = await self._client.request("GET", "/api/v1/logs/query", params=params)
        data = resp.json()
        return data.get("data", {}).get("result", [])

    async def audit_trail(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
        **kwargs: Any,
    ) -> dict:
        params: dict = {"limit": limit}
        if event_type is not None:
            params["event_type"] = event_type
        if severity is not None:
            params["severity"] = severity
        if search is not None:
            params["search"] = search
        if cursor is not None:
            params["cursor"] = cursor
        else:
            params["offset"] = offset
        for k in ("user", "start_time", "end_time"):
            if kwargs.get(k) is not None:
                params[k] = kwargs[k]
        resp = await self._client.request("GET", "/api/v1/audit-trail", params=params)
        data = resp.json()
        return {
            "items": [AuditEntry.model_validate(e) for e in data.get("items", [])],
            "total": data.get("total", 0),
            "next_cursor": data.get("next_cursor"),
        }
