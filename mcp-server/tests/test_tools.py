"""Unit tests for MCP tools with mocked SDK client."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cagent.exceptions import ApiError, NotFoundError
from cagent.models import Cell, CellStatus, DomainPolicyResponse, PaginatedResponse

from cagent_mcp.server import (
    add_domain_policy,
    create_sandbox,
    delete_domain_policy,
    delete_sandbox,
    get_audit_log,
    get_sandbox_status,
    list_domain_policies,
    list_sandboxes,
    restart_sandbox,
    start_sandbox,
    stop_sandbox,
)


@pytest.fixture(autouse=True)
def mock_client():
    """Replace the global SDK client with a mock for every test."""
    client = AsyncMock()
    # Set up resource mocks
    client.cells = AsyncMock()
    client.domain_policies = AsyncMock()
    client.logs = AsyncMock()
    with patch("cagent_mcp.server._client", client):
        with patch("cagent_mcp.server._get_client", return_value=client):
            yield client


# -- Sandbox lifecycle --


@pytest.mark.asyncio
async def test_create_sandbox(mock_client):
    resp = MagicMock()
    resp.json.return_value = {
        "cell_id": "cell-abc123",
        "agent_token": "cag_tok_xxx",
        "status": "provisioning",
    }
    mock_client.request.return_value = resp
    result = json.loads(await create_sandbox(variant="ai"))
    assert result["cell_id"] == "cell-abc123"
    assert result["status"] == "provisioning"
    mock_client.request.assert_called_once_with("POST", "/api/v1/cells", json={"variant": "ai"})


@pytest.mark.asyncio
async def test_create_sandbox_with_ssh_key(mock_client):
    resp = MagicMock()
    resp.json.return_value = {"cell_id": "cell-xyz", "status": "unknown"}
    mock_client.request.return_value = resp
    result = json.loads(await create_sandbox(variant="dev", ssh_public_key="ssh-ed25519 AAAA..."))
    assert result["cell_id"] == "cell-xyz"
    mock_client.request.assert_called_once_with(
        "POST", "/api/v1/cells", json={"variant": "dev", "ssh_public_key": "ssh-ed25519 AAAA..."}
    )


@pytest.mark.asyncio
async def test_list_sandboxes(mock_client):
    mock_client.cells.list.return_value = PaginatedResponse[Cell](
        items=[], total=0, limit=50, offset=0
    )
    result = json.loads(await list_sandboxes())
    assert result["items"] == []
    mock_client.cells.list.assert_called_once_with(limit=50)


@pytest.mark.asyncio
async def test_get_sandbox_status(mock_client):
    mock_client.cells.get.return_value = CellStatus(
        cell_id="cell-abc", status="running", cpu_percent=12, memory_mb=256, online=True
    )
    result = json.loads(await get_sandbox_status("cell-abc"))
    assert result["status"] == "running"
    assert result["cpu_percent"] == 12
    mock_client.cells.get.assert_called_once_with("cell-abc")


@pytest.mark.asyncio
async def test_delete_sandbox(mock_client):
    resp = MagicMock()
    resp.json.return_value = {"status": "torn_down", "cell_id": "cell-abc"}
    mock_client.request.return_value = resp
    result = json.loads(await delete_sandbox("cell-abc"))
    assert result["cell_id"] == "cell-abc"
    mock_client.request.assert_called_once_with("DELETE", "/api/v1/cells/cell-abc")


@pytest.mark.asyncio
async def test_start_sandbox(mock_client):
    mock_client.cells.start.return_value = {"status": "command_sent", "command": "start"}
    result = json.loads(await start_sandbox("cell-abc"))
    assert result["command"] == "start"
    mock_client.cells.start.assert_called_once_with("cell-abc")


@pytest.mark.asyncio
async def test_stop_sandbox(mock_client):
    mock_client.cells.stop.return_value = {"status": "command_sent", "command": "stop"}
    result = json.loads(await stop_sandbox("cell-abc"))
    assert result["command"] == "stop"
    mock_client.cells.stop.assert_called_once_with("cell-abc")


@pytest.mark.asyncio
async def test_restart_sandbox(mock_client):
    mock_client.cells.restart.return_value = {"status": "command_sent", "command": "restart"}
    result = json.loads(await restart_sandbox("cell-abc"))
    assert result["command"] == "restart"
    mock_client.cells.restart.assert_called_once_with("cell-abc")


# -- Domain policies --


@pytest.mark.asyncio
async def test_list_domain_policies(mock_client):
    from datetime import datetime

    mock_client.domain_policies.list.return_value = PaginatedResponse[DomainPolicyResponse](
        items=[DomainPolicyResponse(id=1, domain="api.openai.com", created_at=datetime.min, updated_at=datetime.min)],
        total=1, limit=100, offset=0,
    )
    result = json.loads(await list_domain_policies())
    assert len(result["items"]) == 1
    mock_client.domain_policies.list.assert_called_once_with(limit=100)


@pytest.mark.asyncio
async def test_add_domain_policy(mock_client):
    from datetime import datetime

    mock_client.domain_policies.create.return_value = DomainPolicyResponse(
        id=5, domain="api.github.com", created_at=datetime.min, updated_at=datetime.min
    )
    result = json.loads(await add_domain_policy(domain="api.github.com"))
    assert result["domain"] == "api.github.com"
    mock_client.domain_policies.create.assert_called_once_with(
        domain="api.github.com", description=None, requests_per_minute=None
    )


@pytest.mark.asyncio
async def test_add_domain_policy_with_options(mock_client):
    from datetime import datetime

    mock_client.domain_policies.create.return_value = DomainPolicyResponse(
        id=6, domain="api.openai.com", created_at=datetime.min, updated_at=datetime.min
    )
    await add_domain_policy(domain="api.openai.com", description="OpenAI", requests_per_minute=60)
    mock_client.domain_policies.create.assert_called_once_with(
        domain="api.openai.com", description="OpenAI", requests_per_minute=60
    )


@pytest.mark.asyncio
async def test_delete_domain_policy(mock_client):
    mock_client.domain_policies.delete.return_value = {"status": "deleted"}
    result = json.loads(await delete_domain_policy(policy_id=5))
    assert result["status"] == "deleted"
    mock_client.domain_policies.delete.assert_called_once_with(5)


# -- Audit trail --


@pytest.mark.asyncio
async def test_get_audit_log(mock_client):
    mock_client.logs.audit_trail.return_value = {
        "items": [{"event_type": "domain_policy", "action": "create"}],
        "total": 1,
        "next_cursor": None,
    }
    result = json.loads(await get_audit_log(limit=10))
    assert len(result["items"]) == 1
    mock_client.logs.audit_trail.assert_called_once_with(limit=10, event_type=None)


@pytest.mark.asyncio
async def test_get_audit_log_with_event_type(mock_client):
    mock_client.logs.audit_trail.return_value = {"items": [], "total": 0, "next_cursor": None}
    await get_audit_log(limit=20, event_type="cell")
    mock_client.logs.audit_trail.assert_called_once_with(limit=20, event_type="cell")


# -- Error handling --


@pytest.mark.asyncio
async def test_tool_returns_error_on_not_found(mock_client):
    mock_client.cells.get.side_effect = NotFoundError(404, "Cell not found")
    result = json.loads(await get_sandbox_status("nonexistent"))
    assert result["error"] is True
    assert result["status_code"] == 404
    assert result["detail"] == "Cell not found"


@pytest.mark.asyncio
async def test_tool_returns_error_on_auth_failure(mock_client):
    mock_client.cells.list.side_effect = ApiError(401, "Invalid or expired token")
    result = json.loads(await list_sandboxes())
    assert result["error"] is True
    assert result["status_code"] == 401


@pytest.mark.asyncio
async def test_tool_returns_error_on_conflict(mock_client):
    mock_client.request.side_effect = ApiError(409, "Cell is mid-provisioning")
    result = json.loads(await delete_sandbox("cell-provisioning"))
    assert result["error"] is True
    assert result["status_code"] == 409
    assert "mid-provisioning" in result["detail"]
