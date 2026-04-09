"""Cagent MCP Server — tool definitions for managing secure sandboxes."""

from __future__ import annotations

import json
from typing import Optional

from mcp.server.fastmcp import FastMCP

from cagent.async_client import AsyncCagentClient
from cagent.exceptions import ApiError

from cagent_mcp.config import get_api_token, get_api_url

mcp = FastMCP(
    "cagent",
    instructions="Manage Cagent secure sandboxes for AI agents — create, configure, and monitor isolated execution environments.",
)

_client: Optional[AsyncCagentClient] = None


def _get_client() -> AsyncCagentClient:
    global _client
    if _client is None:
        _client = AsyncCagentClient(base_url=get_api_url(), api_token=get_api_token())
    return _client


def _fmt(data) -> str:
    if hasattr(data, "model_dump"):
        data = data.model_dump()
    return json.dumps(data, indent=2, default=str)


def _error(e: ApiError) -> str:
    return json.dumps({"error": True, "status_code": e.status_code, "detail": e.detail})


# -- Sandbox lifecycle --


@mcp.tool()
async def create_sandbox(variant: str = "ai", ssh_public_key: Optional[str] = None) -> str:
    """Create a new secure sandbox (cell).

    Args:
        variant: Sandbox type — "ai" (full ML stack), "dev" (development tools), "ml" (ML libraries), or "lean" (minimal).
        ssh_public_key: Optional SSH public key for direct access (required for classic hosting mode).
    """
    client = _get_client()
    body: dict = {"variant": variant}
    if ssh_public_key is not None:
        body["ssh_public_key"] = ssh_public_key
    try:
        resp = await client.request("POST", "/api/v1/cells", json=body)
        return _fmt(resp.json())
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def list_sandboxes(
    status: Optional[str] = None,
    online: Optional[bool] = None,
    limit: int = 50,
) -> str:
    """List sandboxes with optional filters.

    Args:
        status: Filter by status — "running", "stopped", "provisioning", "unknown".
        online: Filter by online status (true = currently connected).
        limit: Max results to return (default 50).
    """
    client = _get_client()
    params: dict = {"limit": limit, "offset": 0}
    if status is not None:
        params["status"] = status
    if online is not None:
        params["online"] = str(online).lower()
    try:
        resp = await client.request("GET", "/api/v1/cells", params=params)
        return _fmt(resp.json())
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def get_sandbox_status(cell_id: str) -> str:
    """Get detailed status and metrics for a sandbox.

    Args:
        cell_id: The sandbox (cell) ID.
    """
    client = _get_client()
    try:
        result = await client.cells.get(cell_id)
        return _fmt(result)
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def delete_sandbox(cell_id: str) -> str:
    """Delete a sandbox and clean up its infrastructure.

    Args:
        cell_id: The sandbox (cell) ID to delete.
    """
    client = _get_client()
    try:
        resp = await client.request("DELETE", f"/api/v1/cells/{cell_id}")
        return _fmt(resp.json())
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def start_sandbox(cell_id: str) -> str:
    """Start a stopped sandbox.

    Args:
        cell_id: The sandbox (cell) ID to start.
    """
    client = _get_client()
    try:
        result = await client.cells.start(cell_id)
        return _fmt(result)
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def stop_sandbox(cell_id: str) -> str:
    """Stop a running sandbox.

    Args:
        cell_id: The sandbox (cell) ID to stop.
    """
    client = _get_client()
    try:
        result = await client.cells.stop(cell_id)
        return _fmt(result)
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def restart_sandbox(cell_id: str) -> str:
    """Restart a sandbox.

    Args:
        cell_id: The sandbox (cell) ID to restart.
    """
    client = _get_client()
    try:
        result = await client.cells.restart(cell_id)
        return _fmt(result)
    except ApiError as e:
        return _error(e)


# -- Domain policies --


@mcp.tool()
async def list_domain_policies(limit: int = 100) -> str:
    """List allowed domains (egress policies) for the current tenant.

    Args:
        limit: Max results to return (default 100).
    """
    client = _get_client()
    try:
        result = await client.domain_policies.list(limit=limit)
        return _fmt(result)
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def add_domain_policy(
    domain: str,
    description: Optional[str] = None,
    requests_per_minute: Optional[int] = None,
) -> str:
    """Allow a domain for egress traffic from sandboxes.

    Args:
        domain: Domain to allow (e.g. "api.openai.com", "*.github.com").
        description: Optional human-readable description.
        requests_per_minute: Optional rate limit (requests per minute).
    """
    client = _get_client()
    try:
        result = await client.domain_policies.create(
            domain=domain,
            description=description,
            requests_per_minute=requests_per_minute,
        )
        return _fmt(result)
    except ApiError as e:
        return _error(e)


@mcp.tool()
async def delete_domain_policy(policy_id: int) -> str:
    """Remove a domain from the allowlist.

    Args:
        policy_id: The domain policy ID to delete.
    """
    client = _get_client()
    try:
        result = await client.domain_policies.delete(policy_id)
        return _fmt(result)
    except ApiError as e:
        return _error(e)


# -- Audit trail --


@mcp.tool()
async def get_audit_log(limit: int = 50, event_type: Optional[str] = None) -> str:
    """Query the audit trail for the current tenant. Shows policy changes, cell operations, and security events.

    Args:
        limit: Max entries to return (default 50).
        event_type: Optional filter by event type (e.g. "domain_policy", "cell", "token").
    """
    client = _get_client()
    try:
        result = await client.logs.audit_trail(limit=limit, event_type=event_type)
        return _fmt(result)
    except ApiError as e:
        return _error(e)


def main() -> None:
    """Entry point for the cagent-mcp CLI."""
    # Validate required env vars at startup for clear error reporting
    get_api_token()
    mcp.run()


if __name__ == "__main__":
    main()
