"""Tests for CellsResource."""

from httpx import Response

from cagent.models import Cell, CellStatus
from tests.conftest import SAMPLE_CELL, SAMPLE_CELL_STATUS


def test_list_cells(client, mock_api):
    mock_api.get("/api/v1/cells").mock(
        return_value=Response(
            200,
            json={
                "items": [SAMPLE_CELL],
                "total": 1,
                "limit": 100,
                "offset": 0,
            },
        )
    )
    result = client.cells.list()
    assert result.total == 1
    assert isinstance(result.items[0], Cell)
    assert result.items[0].cell_id == "cell-abc"
    assert result.items[0].online is True


def test_get_cell(client, mock_api):
    mock_api.get("/api/v1/cells/cell-abc/status").mock(
        return_value=Response(200, json=SAMPLE_CELL_STATUS)
    )
    status = client.cells.get("cell-abc")
    assert isinstance(status, CellStatus)
    assert status.cpu_percent == 15
    assert status.memory_mb == 256
    assert status.public_ip == "1.2.3.4"


def test_wipe_cell(client, mock_api):
    mock_api.post("/api/v1/cells/cell-abc/wipe").mock(
        return_value=Response(200, json={"status": "command_queued"})
    )
    result = client.cells.wipe("cell-abc")
    assert result["status"] == "command_queued"


def test_wipe_cell_with_workspace(client, mock_api):
    route = mock_api.post("/api/v1/cells/cell-abc/wipe").mock(
        return_value=Response(200, json={"status": "command_queued"})
    )
    client.cells.wipe("cell-abc", workspace=True)
    request = route.calls[0].request
    assert b'"wipe_workspace": true' in request.content or b'"wipe_workspace":true' in request.content


def test_restart_cell(client, mock_api):
    mock_api.post("/api/v1/cells/cell-abc/restart").mock(
        return_value=Response(200, json={"status": "command_queued"})
    )
    result = client.cells.restart("cell-abc")
    assert result["status"] == "command_queued"


def test_stop_cell(client, mock_api):
    mock_api.post("/api/v1/cells/cell-abc/stop").mock(
        return_value=Response(200, json={"status": "command_queued"})
    )
    result = client.cells.stop("cell-abc")
    assert result["status"] == "command_queued"


def test_start_cell(client, mock_api):
    mock_api.post("/api/v1/cells/cell-abc/start").mock(
        return_value=Response(200, json={"status": "command_queued"})
    )
    result = client.cells.start("cell-abc")
    assert result["status"] == "command_queued"


def test_assign_profile(client, mock_api):
    mock_api.put("/api/v1/cells/cell-abc/profile").mock(
        return_value=Response(
            200,
            json={"cell_id": "cell-abc", "profile_id": 1, "profile_name": "default"},
        )
    )
    result = client.cells.assign_profile("cell-abc", 1)
    assert result["profile_id"] == 1


def test_unassign_profile(client, mock_api):
    mock_api.delete("/api/v1/cells/cell-abc/profile").mock(
        return_value=Response(200, json={"cell_id": "cell-abc", "profile_id": None})
    )
    result = client.cells.unassign_profile("cell-abc")
    assert result["profile_id"] is None
