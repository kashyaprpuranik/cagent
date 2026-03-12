import logging
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from constants import CAGENT_CONFIG_PATH, COREDNS_CONTAINER_NAME, docker_client
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter()

# Only allow valid DNS domain characters to prevent command injection in nslookup
# Also disallow starting with '-' to prevent flag injection in subprocess calls
_VALID_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9._][a-zA-Z0-9._-]*$")


# ---------------------------------------------------------------------------
# OpenObserve helpers (lazy import so module loads even without OO)
# ---------------------------------------------------------------------------

def _oo_available() -> bool:
    """Check if OpenObserve client is importable and healthy."""
    try:
        from openobserve_client import is_openobserve_healthy

        return is_openobserve_healthy()
    except ImportError:
        return False


def _oo_query(sql: str, window_hours: int) -> list[dict]:
    """Run a SQL query against OpenObserve for the given time window."""
    try:
        from openobserve_client import datetime_to_us, now_us, query_openobserve

        end_us = now_us()
        start_us = end_us - window_hours * 3600 * 1_000_000
        return query_openobserve(sql, start_us, end_us)
    except ImportError:
        logger.warning("openobserve_client not available")
        return []
    except Exception as e:
        logger.warning("OpenObserve query failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Widget query functions
# ---------------------------------------------------------------------------

def _query_blocked_domains_top(params: dict) -> list[list]:
    window_hours = params.get("window_hours", 24)
    limit = params.get("limit", 10)
    sql = (
        'SELECT authority as domain, COUNT(*) as count, MAX(_timestamp) as last_seen '
        'FROM "cagent_logs" '
        "WHERE source = 'envoy' AND log_type = 'access' AND response_code = 403 "
        'GROUP BY authority '
        'ORDER BY count DESC '
        f'LIMIT {int(limit)}'
    )
    rows = _oo_query(sql, window_hours)
    return [[r.get("domain", ""), r.get("count", 0), r.get("last_seen", "")] for r in rows]


def _query_blocked_timeseries(params: dict) -> list[list]:
    window_hours = params.get("window_hours", 24)
    buckets = params.get("buckets", 12)
    interval_min = max(1, int(window_hours * 60 / buckets))
    sql = (
        f"SELECT FLOOR(_timestamp / {interval_min * 60 * 1_000_000}) * {interval_min * 60 * 1_000_000} as bucket, "
        'COUNT(*) as count '
        'FROM "cagent_logs" '
        "WHERE source = 'envoy' AND log_type = 'access' AND response_code = 403 "
        'GROUP BY bucket '
        'ORDER BY bucket'
    )
    rows = _oo_query(sql, window_hours)
    return [[r.get("bucket", 0), r.get("count", 0)] for r in rows]


def _query_bandwidth_by_domain(params: dict) -> list[list]:
    window_hours = params.get("window_hours", 24)
    limit = params.get("limit", 10)
    sql = (
        'SELECT authority as domain, '
        'SUM(bytes_sent) as bytes_sent, '
        'SUM(bytes_received) as bytes_received, '
        'SUM(bytes_sent) + SUM(bytes_received) as total_bytes '
        'FROM "cagent_logs" '
        "WHERE source = 'envoy' AND log_type = 'access' "
        'GROUP BY authority '
        'ORDER BY total_bytes DESC '
        f'LIMIT {int(limit)}'
    )
    rows = _oo_query(sql, window_hours)
    return [
        [r.get("domain", ""), r.get("bytes_sent", 0), r.get("bytes_received", 0), r.get("total_bytes", 0)]
        for r in rows
    ]


def _query_requests_by_status(params: dict) -> list[list]:
    window_hours = params.get("window_hours", 24)
    sql = (
        'SELECT response_code as status_code, COUNT(*) as count '
        'FROM "cagent_logs" '
        "WHERE source = 'envoy' AND log_type = 'access' "
        'GROUP BY response_code '
        'ORDER BY count DESC'
    )
    rows = _oo_query(sql, window_hours)
    return [[r.get("status_code", 0), r.get("count", 0)] for r in rows]


def _query_request_volume(params: dict) -> list[list]:
    window_hours = params.get("window_hours", 24)
    buckets = params.get("buckets", 12)
    interval_min = max(1, int(window_hours * 60 / buckets))
    interval_us = interval_min * 60 * 1_000_000
    sql = (
        f'SELECT FLOOR(_timestamp / {interval_us}) * {interval_us} as bucket, '
        'COUNT(*) as total, '
        "SUM(CASE WHEN response_code = 403 THEN 1 ELSE 0 END) as blocked, "
        "SUM(CASE WHEN rate_limited IS NOT NULL AND rate_limited != '' THEN 1 ELSE 0 END) as rate_limited "
        'FROM "cagent_logs" '
        "WHERE source = 'envoy' AND log_type = 'access' "
        'GROUP BY bucket '
        'ORDER BY bucket'
    )
    rows = _oo_query(sql, window_hours)
    return [
        [r.get("bucket", 0), r.get("total", 0), r.get("blocked", 0), r.get("rate_limited", 0)]
        for r in rows
    ]


def _query_latency_by_domain(params: dict) -> list[list]:
    window_hours = params.get("window_hours", 24)
    limit = params.get("limit", 10)
    sql = (
        'SELECT authority as domain, '
        'COUNT(*) as request_count, '
        'AVG(duration_ms) as avg_ms, '
        'MAX(duration_ms) as max_ms '
        'FROM "cagent_logs" '
        "WHERE source = 'envoy' AND log_type = 'access' "
        'GROUP BY authority '
        'ORDER BY avg_ms DESC '
        f'LIMIT {int(limit)}'
    )
    rows = _oo_query(sql, window_hours)
    return [
        [
            r.get("domain", ""),
            r.get("request_count", 0),
            round(r.get("avg_ms", 0), 1),
            r.get("max_ms", 0),
        ]
        for r in rows
    ]


def _query_credential_usage(params: dict) -> list[list]:
    window_hours = params.get("window_hours", 24)
    limit = params.get("limit", 10)
    sql = (
        'SELECT authority as domain, '
        'COUNT(*) as total_requests, '
        "SUM(CASE WHEN credential_injected = 'true' THEN 1 ELSE 0 END) as injected_count "
        'FROM "cagent_logs" '
        "WHERE source = 'envoy' AND log_type = 'access' "
        'GROUP BY authority '
        'ORDER BY injected_count DESC '
        f'LIMIT {int(limit)}'
    )
    rows = _oo_query(sql, window_hours)
    return [
        [r.get("domain", ""), r.get("total_requests", 0), r.get("injected_count", 0)]
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Widget registry
# ---------------------------------------------------------------------------

WIDGET_REGISTRY: dict[str, dict[str, Any]] = {
    "blocked_domains_top": {
        "name": "Top Blocked Domains",
        "category": "security",
        "visualization": "bar_horizontal",
        "default_params": {"window_hours": 24, "limit": 10},
        "columns": [
            {"name": "domain", "type": "string", "role": "dimension"},
            {"name": "count", "type": "number", "role": "measure"},
            {"name": "last_seen", "type": "datetime", "role": "info"},
        ],
        "query_fn": _query_blocked_domains_top,
    },
    "blocked_timeseries": {
        "name": "Blocked Requests Over Time",
        "category": "security",
        "visualization": "line",
        "default_params": {"window_hours": 24, "buckets": 12},
        "columns": [
            {"name": "bucket", "type": "datetime", "role": "dimension"},
            {"name": "count", "type": "number", "role": "measure"},
        ],
        "query_fn": _query_blocked_timeseries,
    },
    "bandwidth_by_domain": {
        "name": "Bandwidth by Domain",
        "category": "performance",
        "visualization": "bar_horizontal",
        "default_params": {"window_hours": 24, "limit": 10},
        "columns": [
            {"name": "domain", "type": "string", "role": "dimension"},
            {"name": "bytes_sent", "type": "number", "role": "measure"},
            {"name": "bytes_received", "type": "number", "role": "measure"},
            {"name": "total_bytes", "type": "number", "role": "measure"},
        ],
        "query_fn": _query_bandwidth_by_domain,
    },
    "requests_by_status": {
        "name": "Requests by Status Code",
        "category": "overview",
        "visualization": "donut",
        "default_params": {"window_hours": 24},
        "columns": [
            {"name": "status_code", "type": "number", "role": "dimension"},
            {"name": "count", "type": "number", "role": "measure"},
        ],
        "query_fn": _query_requests_by_status,
    },
    "request_volume": {
        "name": "Request Volume",
        "category": "overview",
        "visualization": "stacked_area",
        "default_params": {"window_hours": 24, "buckets": 12},
        "columns": [
            {"name": "bucket", "type": "datetime", "role": "dimension"},
            {"name": "total", "type": "number", "role": "measure"},
            {"name": "blocked", "type": "number", "role": "measure"},
            {"name": "rate_limited", "type": "number", "role": "measure"},
        ],
        "query_fn": _query_request_volume,
    },
    "latency_by_domain": {
        "name": "Latency Percentiles by Domain",
        "category": "performance",
        "visualization": "table",
        "default_params": {"window_hours": 24, "limit": 10},
        "columns": [
            {"name": "domain", "type": "string", "role": "dimension"},
            {"name": "request_count", "type": "number", "role": "info"},
            {"name": "avg_ms", "type": "number", "role": "measure"},
            {"name": "max_ms", "type": "number", "role": "measure"},
        ],
        "query_fn": _query_latency_by_domain,
    },
    "credential_usage": {
        "name": "Credential Injection by Domain",
        "category": "security",
        "visualization": "bar_horizontal",
        "default_params": {"window_hours": 24, "limit": 10},
        "columns": [
            {"name": "domain", "type": "string", "role": "dimension"},
            {"name": "total_requests", "type": "number", "role": "measure"},
            {"name": "injected_count", "type": "number", "role": "measure"},
        ],
        "query_fn": _query_credential_usage,
    },
}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class WidgetQueryRequest(BaseModel):
    type: str
    params: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/analytics/types")
def get_widget_types():
    """Return list of available widget types."""
    widgets = []
    for widget_id, spec in WIDGET_REGISTRY.items():
        widgets.append({
            "type": widget_id,
            "name": spec["name"],
            "category": spec["category"],
            "visualization": spec["visualization"],
            "default_params": spec["default_params"],
            "columns": spec["columns"],
        })
    return {"widgets": widgets}


@router.post("/analytics/query")
def query_widget(body: WidgetQueryRequest):
    """Execute a widget query and return columnar data."""
    widget_id = body.type
    if widget_id not in WIDGET_REGISTRY:
        raise HTTPException(status_code=400, detail=f"Unknown widget type: {widget_id}")

    spec = WIDGET_REGISTRY[widget_id]
    merged_params = {**spec["default_params"]}
    if body.params:
        merged_params.update(body.params)

    meta: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    # Include relevant params in meta
    for key in ("window_hours", "limit", "buckets"):
        if key in merged_params:
            meta[key] = merged_params[key]

    if not _oo_available():
        meta["note"] = "OpenObserve unavailable, returning empty results"
        rows: list = []
    else:
        rows = spec["query_fn"](merged_params)

    return {
        "widget": widget_id,
        "visualization": spec["visualization"],
        "columns": spec["columns"],
        "rows": rows,
        "meta": meta,
    }


# ---------------------------------------------------------------------------
# Diagnose endpoint (kept as-is)
# ---------------------------------------------------------------------------

@router.get("/analytics/diagnose")
def diagnose_domain(
    domain: str = Query(..., min_length=1),
):
    """Diagnose why a domain was blocked. Checks allowlist, DNS, and recent logs."""
    # Validate domain format to prevent command injection
    if not _VALID_DOMAIN_RE.match(domain) or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # Check allowlist
    in_allowlist = False
    try:
        config_path = Path(CAGENT_CONFIG_PATH)
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text()) or {}
            allowed_domains = [d.get("domain", "") for d in config.get("domains", [])]
            in_allowlist = domain in allowed_domains
    except Exception as e:
        logger.warning("Failed to parse allowlist from cagent.yaml: %s", e)

    # Check DNS resolution via CoreDNS
    dns_result = None
    try:
        docker_client.containers.get(COREDNS_CONTAINER_NAME)
        # Get CoreDNS IP from container networks
        dns_ip = "10.200.1.5"
        result = subprocess.run(
            ["docker", "exec", COREDNS_CONTAINER_NAME, "nslookup", domain, dns_ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if "NXDOMAIN" in result.stdout or "NXDOMAIN" in result.stderr:
            dns_result = "NXDOMAIN"
        elif result.returncode == 0:
            # Extract first resolved address
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Address") and ":" in line and dns_ip not in line:
                    dns_result = line.split(":")[-1].strip()
                    break
            if not dns_result:
                dns_result = "resolved"
        else:
            dns_result = "NXDOMAIN"
    except Exception:
        dns_result = "unknown"

    # Get recent log entries for this domain via OpenObserve
    recent_requests: list[dict] = []
    try:
        from openobserve_client import _STREAM, datetime_to_us, now_us, query_openobserve

        end_us = now_us()
        start_us = end_us - 1 * 3600 * 1_000_000  # last 1 hour
        escaped = domain.replace("'", "''")
        sql = (
            f'SELECT _timestamp, method, path, response_code, response_flags, duration_ms '
            f'FROM "{_STREAM}" '
            f"WHERE source = 'envoy' AND log_type = 'access' AND authority = '{escaped}' "
            f'ORDER BY _timestamp DESC LIMIT 5'
        )
        rows = query_openobserve(sql, start_us, end_us)
        for r in rows:
            recent_requests.append({
                "timestamp": r.get("_timestamp", ""),
                "method": r.get("method", ""),
                "path": r.get("path", ""),
                "response_code": int(r.get("response_code", 0)),
                "response_flags": r.get("response_flags", ""),
                "duration_ms": int(r.get("duration_ms", 0)),
            })
    except ImportError:
        logger.warning("openobserve_client not available for diagnose")
    except Exception as e:
        logger.warning("Failed to query recent requests: %s", e)

    # Build human-readable diagnosis
    parts = []
    if in_allowlist:
        parts.append("Domain is in the allowlist.")
    else:
        parts.append("Domain is not in the allowlist.")

    if dns_result == "NXDOMAIN":
        parts.append("DNS returns NXDOMAIN (blocked by CoreDNS catch-all).")
    elif dns_result and dns_result != "unknown":
        parts.append(f"DNS resolves to {dns_result}.")

    if recent_requests:
        code = recent_requests[0]["response_code"]
        flags = recent_requests[0]["response_flags"]
        if code == 403:
            parts.append(f"Proxy returns 403{f' (flags: {flags})' if flags else ''}.")
        else:
            parts.append(f"Most recent response: HTTP {code}.")

    return {
        "domain": domain,
        "in_allowlist": in_allowlist,
        "dns_result": dns_result,
        "recent_requests": recent_requests,
        "diagnosis": " ".join(parts),
    }
