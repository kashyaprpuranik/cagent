"""Log query and audit trail."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from cagent.models import AuditEntry

if TYPE_CHECKING:
    from cagent.client import CagentClient


class LogsResource:
    """Query logs and audit trail via the CP API."""

    def __init__(self, client: CagentClient) -> None:
        self._client = client

    def query(
        self,
        query: str = "",
        source: Optional[str] = None,
        cell_id: Optional[str] = None,
        limit: int = 100,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> list[dict]:
        """Query cell logs (proxied through CP to warden/OpenObserve).

        Args:
            query: Search query string.
            source: Filter by log source (e.g. "envoy", "coredns").
            cell_id: Filter by cell ID.
            limit: Max results (default 100, max 1000).
            start: ISO datetime start range.
            end: ISO datetime end range.

        Returns:
            List of log entries (raw dicts from OpenObserve).
        """
        params: dict[str, Any] = {"query": query, "limit": limit}
        if source is not None:
            params["source"] = source
        if cell_id is not None:
            params["cell_id"] = cell_id
        if start is not None:
            params["start"] = start
        if end is not None:
            params["end"] = end
        resp = self._client.request("GET", "/api/v1/logs/query", params=params)
        data = resp.json()
        return data.get("data", {}).get("result", [])

    def audit_trail(
        self,
        event_type: Optional[str] = None,
        user: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> dict:
        """Query audit trail entries.

        Args:
            event_type: Filter by event type (e.g. "egress_policy_created").
            user: Filter by user (partial match).
            severity: Filter by severity ("INFO", "WARNING", "ERROR").
            search: Full-text search across event_type, action, details.
            start_time: ISO datetime start range.
            end_time: ISO datetime end range.
            limit: Max results (default 100, max 1000).
            offset: Offset for pagination (ignored if cursor is set).
            cursor: Cursor for keyset pagination (format: "id:iso-timestamp").

        Returns:
            Dict with keys: items (list of AuditEntry), total, next_cursor.
        """
        params: dict[str, Any] = {"limit": limit}
        if event_type is not None:
            params["event_type"] = event_type
        if user is not None:
            params["user"] = user
        if severity is not None:
            params["severity"] = severity
        if search is not None:
            params["search"] = search
        if start_time is not None:
            params["start_time"] = start_time
        if end_time is not None:
            params["end_time"] = end_time
        if cursor is not None:
            params["cursor"] = cursor
        else:
            params["offset"] = offset
        resp = self._client.request("GET", "/api/v1/audit-trail", params=params)
        data = resp.json()
        return {
            "items": [AuditEntry.model_validate(e) for e in data.get("items", [])],
            "total": data.get("total", 0),
            "next_cursor": data.get("next_cursor"),
        }
