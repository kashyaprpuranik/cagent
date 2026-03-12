import json
import logging
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from constants import CAGENT_CONFIG_PATH, COREDNS_CONTAINER_NAME, DATA_PLANE_DIR, docker_client
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
# Widget registry (loaded from JSON config)
# ---------------------------------------------------------------------------

_WIDGETS_JSON_PATH = Path(DATA_PLANE_DIR) / "configs" / "widgets.json"
if not _WIDGETS_JSON_PATH.exists():
    # Fallback for test environments where DATA_PLANE_DIR differs
    _WIDGETS_JSON_PATH = Path(__file__).resolve().parents[3] / "configs" / "widgets.json"
_CONFIG: dict[str, Any] = json.loads(_WIDGETS_JSON_PATH.read_text())
WIDGET_REGISTRY: dict[str, dict[str, Any]] = _CONFIG["widgets"]
ALERT_REGISTRY: dict[str, dict[str, Any]] = _CONFIG.get("alerts", {})


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

    # Compute derived interval params for timeseries widgets
    if "buckets" in merged_params:
        window_hours = merged_params["window_hours"]
        buckets = merged_params["buckets"]
        interval_min = max(1, int(window_hours * 60 / buckets))
        merged_params["interval_min"] = interval_min
        merged_params["interval_us"] = interval_min * 60 * 1_000_000

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
        # Format SQL template with int params only (validated as ints)
        int_params = {k: int(v) for k, v in merged_params.items() if isinstance(v, (int, float))}
        sql = spec["sql"].format(**int_params)
        window_hours = merged_params["window_hours"]
        raw_rows = _oo_query(sql, window_hours)

        # Generic row mapper: extract column values in order, round floats
        columns = spec["columns"]
        rows = []
        for r in raw_rows:
            row = []
            for col in columns:
                val = r.get(col["name"])
                if val is None:
                    val = "" if col["type"] == "string" else 0
                if col["type"] == "number" and isinstance(val, float):
                    val = round(val, 1)
                row.append(val)
            rows.append(row)

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
    except Exception as e:
        logger.debug("DNS resolution failed for domain lookup: %s", e)
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
