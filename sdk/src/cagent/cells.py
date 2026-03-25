"""Cell management."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cagent.models import Cell, CellStatus, PaginatedResponse

if TYPE_CHECKING:
    from cagent.client import CagentClient


class CellsResource:
    """Manages cells via the CP API."""

    def __init__(self, client: CagentClient) -> None:
        self._client = client

    def list(self, limit: int = 100, offset: int = 0) -> PaginatedResponse[Cell]:
        """List cells."""
        resp = self._client.request("GET", "/api/v1/cells", params={"limit": limit, "offset": offset})
        data = resp.json()
        return PaginatedResponse[Cell](
            items=[Cell.model_validate(c) for c in data["items"]],
            total=data["total"],
            limit=data["limit"],
            offset=data["offset"],
        )

    def get(self, cell_id: str) -> CellStatus:
        """Get detailed cell status."""
        resp = self._client.request("GET", f"/api/v1/cells/{cell_id}/status")
        return CellStatus.model_validate(resp.json())

    def command(self, cell_id: str, command: str) -> dict:
        """Send a command to a cell. Valid: wipe, wipe-workspace, restart, stop, start."""
        resp = self._client.request("POST", f"/api/v1/cells/{cell_id}/{command}")
        return resp.json()

    def wipe(self, cell_id: str, workspace: bool = False) -> dict:
        """Wipe a cell. Optionally wipe the workspace too."""
        return self.command(cell_id, "wipe-workspace" if workspace else "wipe")

    def restart(self, cell_id: str) -> dict:
        """Restart a cell."""
        return self.command(cell_id, "restart")

    def stop(self, cell_id: str) -> dict:
        """Stop a cell."""
        return self.command(cell_id, "stop")

    def start(self, cell_id: str) -> dict:
        """Start a cell."""
        return self.command(cell_id, "start")

    def assign_profile(self, cell_id: str, profile_id: int) -> dict:
        """Assign a security profile to a cell."""
        resp = self._client.request(
            "PUT",
            f"/api/v1/cells/{cell_id}/profile",
            json={"profile_id": profile_id},
        )
        return resp.json()

    def unassign_profile(self, cell_id: str) -> dict:
        """Unassign the security profile from a cell (revert to baseline)."""
        resp = self._client.request("DELETE", f"/api/v1/cells/{cell_id}/profile")
        return resp.json()
