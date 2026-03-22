"""Synchronous Cagent client."""

from __future__ import annotations

from typing import Any

import httpx

from cagent.auth import auth_headers, resolve_token
from cagent.exceptions import ApiError, AuthenticationError, NotFoundError
from cagent.models import AuthInfo


class CagentClient:
    """Synchronous client for the Cagent Control Plane API.

    Usage::

        from cagent import CagentClient

        with CagentClient(api_token="cag_...") as client:
            profiles = client.profiles.list()
    """

    def __init__(
        self,
        base_url: str = "https://app.cagent-control.com",
        api_token: str | None = None,
        timeout: float = 30.0,
        httpx_client: httpx.Client | None = None,
    ):
        token = resolve_token(api_token)
        self._base_url = base_url.rstrip("/")
        self._client = httpx_client or httpx.Client(
            base_url=self._base_url,
            timeout=timeout,
            headers=auth_headers(token),
        )

        # Lazy imports to avoid circular deps
        from cagent.cells import CellsResource
        from cagent.dlp_policies import DlpPoliciesResource
        from cagent.domain_policies import DomainPoliciesResource
        from cagent.logs import LogsResource
        from cagent.profiles import ProfilesResource

        self.profiles = ProfilesResource(self)
        self.cells = CellsResource(self)
        self.domain_policies = DomainPoliciesResource(self)
        self.dlp = DlpPoliciesResource(self)
        self.logs = LogsResource(self)

    def me(self) -> AuthInfo:
        """Get current user/token info (GET /api/v1/auth/me)."""
        resp = self.request("GET", "/api/v1/auth/me")
        return AuthInfo.model_validate(resp.json())

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Make an authenticated request with error handling."""
        resp = self._client.request(method, path, **kwargs)
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

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> CagentClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def _extract_detail(resp: httpx.Response) -> str:
    """Extract error detail from a response."""
    try:
        body = resp.json()
        if isinstance(body, dict):
            return str(body.get("detail", resp.text))
    except Exception:
        pass
    return resp.text
