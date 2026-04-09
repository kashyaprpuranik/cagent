"""Tests for the cagent CLI."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cagent.cli import app
from cagent.exceptions import ApiError, NotFoundError
from cagent.models import (
    Cell,
    CellStatus,
    CommunityProfile,
    DomainPolicyResponse,
    PaginatedResponse,
    SecurityProfile,
)

runner = CliRunner()

from datetime import datetime

NOW = datetime.min


def _mock_client():
    """Create a mock CagentClient with all resources."""
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    return client


# -- Profile commands --


@patch("cagent.cli._client")
def test_profile_list(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.profiles.list.return_value = PaginatedResponse[SecurityProfile](
        items=[
            SecurityProfile(id=1, tenant_id=1, name="default", created_at=NOW, updated_at=NOW),
            SecurityProfile(id=2, tenant_id=1, name="strict", description="Locked down", created_at=NOW, updated_at=NOW),
        ],
        total=2, limit=100, offset=0,
    )
    result = runner.invoke(app, ["profile", "list"])
    assert result.exit_code == 0
    assert "default" in result.output
    assert "strict" in result.output
    assert "2 profile(s)" in result.output


@patch("cagent.cli._client")
def test_profile_show_by_id(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.profiles.get.return_value = SecurityProfile(
        id=1, tenant_id=1, name="default", created_at=NOW, updated_at=NOW
    )
    result = runner.invoke(app, ["profile", "show", "1"])
    assert result.exit_code == 0
    assert '"name": "default"' in result.output


@patch("cagent.cli._client")
def test_profile_community(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.profiles.list_community.return_value = [
        CommunityProfile(file="research-agent.json", name="research-agent", description="Research tools", icon="🔬"),
    ]
    result = runner.invoke(app, ["profile", "community"])
    assert result.exit_code == 0
    assert "research-agent" in result.output
    assert "1 community profile(s)" in result.output


@patch("cagent.cli._client")
def test_profile_apply(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    from cagent.models import ProfileImportResult
    client.profiles.apply.return_value = ProfileImportResult(
        profile_id=1, profile_name="default", domain_policies_created=5,
        email_policies_created=0, dlp_updated=True, profile_updated=True,
    )
    result = runner.invoke(app, ["profile", "apply", "research-agent"])
    assert result.exit_code == 0
    assert "Applied to profile 'default'" in result.output
    assert "domain policies created: 5" in result.output


# -- Cell commands --


@patch("cagent.cli._client")
def test_cell_list(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.list.return_value = PaginatedResponse[Cell](
        items=[
            Cell(cell_id="my-agent", status="running", online=True, security_profile_name="default"),
            Cell(cell_id="dev-box", status="stopped", online=False),
        ],
        total=2, limit=100, offset=0,
    )
    result = runner.invoke(app, ["cell", "list"])
    assert result.exit_code == 0
    assert "my-agent" in result.output
    assert "running" in result.output
    assert "2 cell(s)" in result.output


@patch("cagent.cli._client")
def test_cell_list_empty(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.list.return_value = PaginatedResponse[Cell](items=[], total=0, limit=100, offset=0)
    result = runner.invoke(app, ["cell", "list"])
    assert result.exit_code == 0
    assert "No cells found" in result.output


@patch("cagent.cli._client")
def test_cell_status(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.get.return_value = CellStatus(
        cell_id="my-agent", status="running", cpu_percent=12, memory_mb=256, online=True
    )
    result = runner.invoke(app, ["cell", "status", "my-agent"])
    assert result.exit_code == 0
    assert '"status": "running"' in result.output
    assert '"cpu_percent": 12' in result.output


@patch("cagent.cli._client")
def test_cell_stop(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.stop.return_value = {"status": "queued"}
    result = runner.invoke(app, ["cell", "stop", "my-agent"])
    assert result.exit_code == 0
    assert "Stop command sent to my-agent" in result.output


@patch("cagent.cli._client")
def test_cell_start(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.start.return_value = {"status": "queued"}
    result = runner.invoke(app, ["cell", "start", "my-agent"])
    assert result.exit_code == 0
    assert "Start command sent" in result.output


@patch("cagent.cli._client")
def test_cell_restart(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.restart.return_value = {"status": "queued"}
    result = runner.invoke(app, ["cell", "restart", "my-agent"])
    assert result.exit_code == 0
    assert "Restart command sent" in result.output


@patch("cagent.cli._client")
def test_cell_wipe(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.wipe.return_value = {"status": "queued"}
    result = runner.invoke(app, ["cell", "wipe", "my-agent"])
    assert result.exit_code == 0
    assert "Wipe command sent" in result.output
    client.cells.wipe.assert_called_once_with("my-agent", workspace=False)


@patch("cagent.cli._client")
def test_cell_wipe_workspace(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.wipe.return_value = {"status": "queued"}
    result = runner.invoke(app, ["cell", "wipe", "my-agent", "--workspace"])
    assert result.exit_code == 0
    assert "Wipe (with workspace)" in result.output
    client.cells.wipe.assert_called_once_with("my-agent", workspace=True)


# -- Domain commands --


@patch("cagent.cli._client")
def test_domain_list(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.domain_policies.list.return_value = PaginatedResponse[DomainPolicyResponse](
        items=[
            DomainPolicyResponse(id=1, domain="api.openai.com", requests_per_minute=60, has_credential=True, created_at=NOW, updated_at=NOW),
            DomainPolicyResponse(id=2, domain="api.github.com", created_at=NOW, updated_at=NOW),
        ],
        total=2, limit=100, offset=0,
    )
    result = runner.invoke(app, ["domain", "list"])
    assert result.exit_code == 0
    assert "api.openai.com" in result.output
    assert "api.github.com" in result.output
    assert "2 domain policy" in result.output


@patch("cagent.cli._client")
def test_domain_add(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.domain_policies.create.return_value = DomainPolicyResponse(
        id=5, domain="api.anthropic.com", created_at=NOW, updated_at=NOW
    )
    result = runner.invoke(app, ["domain", "add", "api.anthropic.com", "--rpm", "100"])
    assert result.exit_code == 0
    assert "Added domain policy: api.anthropic.com" in result.output
    client.domain_policies.create.assert_called_once_with(
        domain="api.anthropic.com", description=None, requests_per_minute=100
    )


@patch("cagent.cli._client")
def test_domain_remove(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.domain_policies.delete.return_value = {"status": "deleted"}
    result = runner.invoke(app, ["domain", "remove", "5"])
    assert result.exit_code == 0
    assert "Removed domain policy 5" in result.output


# -- Error handling --


@patch("cagent.cli._client")
def test_error_shows_message(mock_factory):
    client = _mock_client()
    mock_factory.return_value = client
    client.cells.get.side_effect = NotFoundError(404, "Cell not found")
    result = runner.invoke(app, ["cell", "status", "nonexistent"])
    assert result.exit_code == 1
    assert "Cell not found" in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "profile" in result.output
    assert "cell" in result.output
    assert "domain" in result.output
