"""Domain policy management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from cagent.models import DomainPolicyResponse, PaginatedResponse

if TYPE_CHECKING:
    from cagent.client import CagentClient


class DomainPoliciesResource:
    """Manages domain policies via the CP API."""

    def __init__(self, client: CagentClient) -> None:
        self._client = client

    def list(
        self,
        profile_id: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> PaginatedResponse[DomainPolicyResponse]:
        """List domain policies, optionally filtered by profile."""
        params: dict = {"limit": limit, "offset": offset}
        if profile_id is not None:
            params["profile_id"] = profile_id
        resp = self._client.request("GET", "/api/v1/domain-policies", params=params)
        data = resp.json()
        return PaginatedResponse[DomainPolicyResponse](
            items=[DomainPolicyResponse.model_validate(p) for p in data["items"]],
            total=data["total"],
            limit=data["limit"],
            offset=data["offset"],
        )

    def get(self, policy_id: int) -> DomainPolicyResponse:
        """Get a domain policy by ID."""
        resp = self._client.request("GET", f"/api/v1/domain-policies/{policy_id}")
        return DomainPolicyResponse.model_validate(resp.json())

    def create(
        self,
        domain: str,
        alias: Optional[str] = None,
        description: Optional[str] = None,
        profile_id: Optional[int] = None,
        allowed_paths: Optional[list[str]] = None,
        requests_per_minute: Optional[int] = None,
        burst_size: Optional[int] = None,
        timeout: Optional[str] = None,
        read_only: Optional[bool] = None,
        credential: Optional[dict] = None,
    ) -> DomainPolicyResponse:
        """Create a new domain policy.

        Args:
            domain: Domain to allow (e.g. "api.openai.com").
            credential: Optional dict with keys: header, format, value.
                Example: {"header": "Authorization", "format": "Bearer {value}", "value": "sk-..."}
        """
        body: dict = {"domain": domain}
        if alias is not None:
            body["alias"] = alias
        if description is not None:
            body["description"] = description
        if profile_id is not None:
            body["profile_id"] = profile_id
        if allowed_paths is not None:
            body["allowed_paths"] = allowed_paths
        if requests_per_minute is not None:
            body["requests_per_minute"] = requests_per_minute
        if burst_size is not None:
            body["burst_size"] = burst_size
        if timeout is not None:
            body["timeout"] = timeout
        if read_only is not None:
            body["read_only"] = read_only
        if credential is not None:
            body["credential"] = credential
        resp = self._client.request("POST", "/api/v1/domain-policies", json=body)
        return DomainPolicyResponse.model_validate(resp.json())

    def update(
        self,
        policy_id: int,
        alias: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
        allowed_paths: Optional[list[str]] = None,
        requests_per_minute: Optional[int] = None,
        burst_size: Optional[int] = None,
        timeout: Optional[str] = None,
        read_only: Optional[bool] = None,
        credential: Optional[dict] = None,
        clear_credential: Optional[bool] = None,
    ) -> DomainPolicyResponse:
        """Update a domain policy."""
        body: dict = {}
        if alias is not None:
            body["alias"] = alias
        if description is not None:
            body["description"] = description
        if enabled is not None:
            body["enabled"] = enabled
        if allowed_paths is not None:
            body["allowed_paths"] = allowed_paths
        if requests_per_minute is not None:
            body["requests_per_minute"] = requests_per_minute
        if burst_size is not None:
            body["burst_size"] = burst_size
        if timeout is not None:
            body["timeout"] = timeout
        if read_only is not None:
            body["read_only"] = read_only
        if credential is not None:
            body["credential"] = credential
        if clear_credential is not None:
            body["clear_credential"] = clear_credential
        resp = self._client.request(
            "PUT", f"/api/v1/domain-policies/{policy_id}", json=body
        )
        return DomainPolicyResponse.model_validate(resp.json())

    def delete(self, policy_id: int) -> dict:
        """Delete a domain policy."""
        resp = self._client.request("DELETE", f"/api/v1/domain-policies/{policy_id}")
        return resp.json()

    def rotate_credential(
        self,
        policy_id: int,
        value: str,
        header: str = "Authorization",
        format: str = "Bearer {value}",
    ) -> DomainPolicyResponse:
        """Rotate the credential for a domain policy.

        Args:
            policy_id: The domain policy ID.
            value: New credential value (e.g. API key).
            header: HTTP header name (default: "Authorization").
            format: Format string with {value} placeholder (default: "Bearer {value}").
        """
        body = {"header": header, "format": format, "value": value}
        resp = self._client.request(
            "POST", f"/api/v1/domain-policies/{policy_id}/rotate-credential", json=body
        )
        return DomainPolicyResponse.model_validate(resp.json())
