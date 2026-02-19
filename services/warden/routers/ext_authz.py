"""Envoy ext_authz endpoint for credential injection.

Implements the ext_authz HTTP service protocol for Envoy.
Domain allow/deny and path filtering are handled by Envoy routing configuration.
This endpoint handles credential injection only.

Returns 200 with credential headers when available.
"""

import logging
import time

import requests
from fastapi import APIRouter, Request
from fastapi.responses import Response
from pathlib import Path

from constants import (
    DATAPLANE_MODE,
    CONTROL_PLANE_URL,
    CONTROL_PLANE_TOKEN,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory cache: domain -> {policy, expires_at}
_policy_cache: dict = {}
_CACHE_TTL = 300  # 5 minutes


def _cache_get(domain: str):
    """Return cached policy if still valid, else None."""
    entry = _policy_cache.get(domain)
    if entry and entry["expires_at"] > time.monotonic():
        return entry["policy"]
    return None


def _cache_set(domain: str, policy):
    """Cache a policy result."""
    _policy_cache[domain] = {
        "policy": policy,
        "expires_at": time.monotonic() + _CACHE_TTL,
    }


def invalidate_cache():
    """Clear the policy cache (called when config is regenerated)."""
    _policy_cache.clear()


def _get_policy_connected(domain: str):
    """Get full domain policy from control plane."""
    try:
        resp = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/domain-policies/for-domain",
            params={"domain": domain},
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json()
    except requests.exceptions.RequestException as e:
        logger.warning(f"CP unreachable for policy lookup: {e}")
    return None


def _get_policy(domain: str) -> dict:
    """Get full domain policy. Returns dict with matched, allowed_paths, credentials, etc."""
    domain_lower = domain.lower()

    # Check cache
    cached = _cache_get(domain_lower)
    if cached is not None:
        return cached

    # Import here to avoid circular imports at module level
    from routers.domain_policy import _build_standalone_policy, _is_devbox_local

    # devbox.local always resolved locally
    if _is_devbox_local(domain_lower):
        policy = _build_standalone_policy(domain_lower)
        _cache_set(domain_lower, policy)
        return policy

    # Connected mode: try CP first
    if DATAPLANE_MODE == "connected" and CONTROL_PLANE_URL and CONTROL_PLANE_TOKEN:
        policy = _get_policy_connected(domain_lower)
        if policy:
            _cache_set(domain_lower, policy)
            return policy
        # Fall through to standalone on CP failure

    # Standalone mode or CP fallback
    policy = _build_standalone_policy(domain_lower)
    _cache_set(domain_lower, policy)
    return policy


@router.api_route(
    "/api/v1/ext-authz/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
async def ext_authz_check(request: Request, path: str = ""):
    """Envoy ext_authz endpoint for credential injection.

    Domain allow/deny and path filtering are handled by Envoy routing.
    This endpoint handles credential injection only.
    Returns 200 with credential headers when available.
    """
    # Extract domain from Host header (Envoy forwards :authority as Host)
    authority = request.headers.get("host", "")
    domain = authority.split(":")[0].lower()

    # Look up full domain policy
    policy = _get_policy(domain)

    # Credential injection
    headers = {"x-credential-injected": "false"}
    header_name = policy.get("header_name")
    header_value = policy.get("header_value")
    if header_name and header_value:
        headers[header_name] = header_value
        headers["x-credential-injected"] = "true"

    return Response(status_code=200, headers=headers)
