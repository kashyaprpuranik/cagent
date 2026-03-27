"""Client for querying the local VictoriaLogs instance.

Used by warden analytics and log search endpoints when VictoriaLogs is running
on the data plane (log-store container).
"""

import json
import logging
from datetime import datetime, timezone

import requests
from constants import VICTORIALOGS_URL

logger = logging.getLogger(__name__)

_INDEX = "cagent_logs"


def is_healthy() -> bool:
    """Check if the local VictoriaLogs instance is reachable."""
    try:
        resp = requests.get(f"{VICTORIALOGS_URL}/health", timeout=3)
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        logger.debug("VictoriaLogs health check failed: %s", e)
        return False


def query_logs(logsql: str, start_us: int, end_us: int) -> list[dict]:
    """Execute a LogsQL query against VictoriaLogs and return raw log entries.

    Args:
        logsql: LogsQL query string.
        start_us: Start time in microseconds since epoch.
        end_us: End time in microseconds since epoch.

    Returns:
        List of log entry dicts (one per matched line).
    """
    url = f"{VICTORIALOGS_URL}/select/logsql/query"
    params = {
        "query": logsql,
        "start": us_to_iso(start_us),
        "end": us_to_iso(end_us),
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code != 200:
            logger.warning("VL query failed: %s %s", resp.status_code, resp.text[:200])
            return []
        # Response is JSON lines (one JSON object per line)
        results = []
        for line in resp.text.strip().splitlines():
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
    except requests.exceptions.RequestException as e:
        logger.warning("VL query error: %s", e)
        return []


def query_stats(logsql: str, start_us: int, end_us: int) -> list[dict]:
    """Execute a LogsQL stats query against VictoriaLogs.

    Uses the /select/logsql/query endpoint which supports stats pipes
    with grouping (by clause). The stats_query endpoint only supports
    single-value aggregations without grouping.

    Args:
        logsql: LogsQL query string with stats pipe (e.g. "source:envoy | stats count() as count by (authority)").
        start_us: Start time in microseconds since epoch.
        end_us: End time in microseconds since epoch.

    Returns:
        List of result dicts from the stats query.
    """
    return query_logs(logsql, start_us, end_us)


def datetime_to_us(dt: datetime) -> int:
    """Convert a datetime to microseconds since epoch."""
    return int(dt.timestamp() * 1_000_000)


def now_us() -> int:
    """Current time in microseconds since epoch."""
    return datetime_to_us(datetime.now(timezone.utc))


def us_to_iso(us: int) -> str:
    """Convert microseconds since epoch to ISO8601 string for VictoriaLogs API."""
    return datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc).isoformat()
