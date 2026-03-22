"""Token authentication for the CP API."""

from __future__ import annotations

import os

from cagent.exceptions import CagentError


def resolve_token(api_token: str | None = None) -> str:
    """Resolve the API token from the argument or CAGENT_API_TOKEN env var."""
    token = api_token or os.environ.get("CAGENT_API_TOKEN")
    if not token:
        raise CagentError(
            "API token required. Pass api_token= or set CAGENT_API_TOKEN env var."
        )
    return token


def auth_headers(token: str) -> dict[str, str]:
    """Return the Authorization header dict."""
    return {"Authorization": f"Bearer {token}"}
