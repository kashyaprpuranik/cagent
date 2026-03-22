"""Tests for LogsResource."""

from httpx import Response

from cagent.models import AuditEntry

SAMPLE_LOG_RESPONSE = {
    "status": "success",
    "data": {
        "resultType": "streams",
        "result": [
            {"_timestamp": "2026-01-01T00:00:00Z", "log": "GET /v1/chat 200", "source": "envoy"},
            {"_timestamp": "2026-01-01T00:00:01Z", "log": "DNS query api.openai.com", "source": "coredns"},
        ],
    },
}

SAMPLE_AUDIT_ENTRY = {
    "id": 42,
    "tenant_id": 1,
    "event_type": "egress_policy_created",
    "action": "Egress policy created: api.openai.com",
    "user": "admin@example.com",
    "severity": "INFO",
    "details": '{"domain": "api.openai.com"}',
    "container_id": None,
    "timestamp": "2026-01-01T00:00:00Z",
}


def test_query_logs(client, mock_api):
    mock_api.get("/api/v1/logs/query").mock(
        return_value=Response(200, json=SAMPLE_LOG_RESPONSE)
    )
    logs = client.logs.query(query="openai", limit=50)
    assert len(logs) == 2
    assert logs[0]["source"] == "envoy"


def test_query_logs_with_filters(client, mock_api):
    route = mock_api.get("/api/v1/logs/query").mock(
        return_value=Response(200, json=SAMPLE_LOG_RESPONSE)
    )
    client.logs.query(source="envoy", cell_id="cell-abc", start="2026-01-01T00:00:00Z")
    request = route.calls[0].request
    url = str(request.url)
    assert "source=envoy" in url
    assert "cell_id=cell-abc" in url
    assert "start=" in url


def test_audit_trail(client, mock_api):
    mock_api.get("/api/v1/audit-trail").mock(
        return_value=Response(
            200,
            json={
                "items": [SAMPLE_AUDIT_ENTRY],
                "total": 1,
                "next_cursor": "42:2026-01-01T00:00:00",
            },
        )
    )
    result = client.logs.audit_trail(event_type="egress_policy_created")
    assert result["total"] == 1
    assert isinstance(result["items"][0], AuditEntry)
    assert result["items"][0].event_type == "egress_policy_created"
    assert result["next_cursor"] == "42:2026-01-01T00:00:00"


def test_audit_trail_cursor_pagination(client, mock_api):
    route = mock_api.get("/api/v1/audit-trail").mock(
        return_value=Response(
            200,
            json={"items": [], "total": 0, "next_cursor": None},
        )
    )
    client.logs.audit_trail(cursor="42:2026-01-01T00:00:00")
    url = str(route.calls[0].request.url)
    assert "cursor=42" in url
    # offset should not be present when cursor is used
    assert "offset=" not in url


def test_audit_trail_search(client, mock_api):
    route = mock_api.get("/api/v1/audit-trail").mock(
        return_value=Response(200, json={"items": [], "total": 0, "next_cursor": None})
    )
    client.logs.audit_trail(search="openai", severity="WARNING")
    url = str(route.calls[0].request.url)
    assert "search=openai" in url
    assert "severity=WARNING" in url
