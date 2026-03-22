"""DLP policy management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from cagent.models import DlpPolicyResponse

if TYPE_CHECKING:
    from cagent.client import CagentClient


class DlpPoliciesResource:
    """Manages DLP (Data Loss Prevention) policies via the CP API."""

    def __init__(self, client: CagentClient) -> None:
        self._client = client

    def get(self, profile_id: Optional[int] = None) -> DlpPolicyResponse:
        """Get the DLP policy for a profile.

        Returns defaults if no DLP policy is configured.

        Args:
            profile_id: Profile ID. If None, returns the default profile's DLP policy.
        """
        params: dict = {}
        if profile_id is not None:
            params["profile_id"] = profile_id
        resp = self._client.request("GET", "/api/v1/dlp-policies", params=params)
        return DlpPolicyResponse.model_validate(resp.json())

    def update(
        self,
        enabled: Optional[bool] = None,
        mode: Optional[str] = None,
        skip_domains: Optional[list[str]] = None,
        custom_patterns: Optional[list[dict]] = None,
        profile_id: Optional[int] = None,
    ) -> DlpPolicyResponse:
        """Create or update a DLP policy (upsert).

        Args:
            enabled: Enable/disable DLP scanning.
            mode: "log", "block", or "redact".
            skip_domains: Domains to skip DLP scanning for.
            custom_patterns: List of {"name": str, "regex": str} dicts.
            profile_id: Target profile. If None, targets the default profile.
        """
        body: dict = {}
        if enabled is not None:
            body["enabled"] = enabled
        if mode is not None:
            body["mode"] = mode
        if skip_domains is not None:
            body["skip_domains"] = skip_domains
        if custom_patterns is not None:
            body["custom_patterns"] = custom_patterns
        params: dict = {}
        if profile_id is not None:
            params["profile_id"] = profile_id
        resp = self._client.request(
            "PUT", "/api/v1/dlp-policies", json=body, params=params
        )
        return DlpPolicyResponse.model_validate(resp.json())
