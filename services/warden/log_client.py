"""Unified log query client — dispatches to DuckDB (lightweight) or OpenObserve (auditing).

Callers import from this module instead of openobserve_client or duckdb_log_client directly.
The backend is selected via the LOG_BACKEND env var:
  - "duckdb" (default): reads Vector's NDJSON backup files with DuckDB
  - "openobserve": uses the OpenObserve API (requires auditing profile)
"""

import logging
import os

logger = logging.getLogger(__name__)

_STREAM = "cagent_logs"
_BACKEND = os.environ.get("LOG_BACKEND", "duckdb")


def is_log_store_healthy() -> bool:
    """Check if the active log backend is healthy."""
    if _BACKEND == "openobserve":
        try:
            from openobserve_client import is_openobserve_healthy

            return is_openobserve_healthy()
        except ImportError:
            return False
    from duckdb_log_client import is_healthy

    return is_healthy()


def query_logs(sql: str, start_us: int, end_us: int) -> list[dict]:
    """Execute a SQL query against the active log backend.

    Args:
        sql: SQL query string (using "cagent_logs" as table name).
        start_us: Start time in microseconds since epoch.
        end_us: End time in microseconds since epoch.

    Returns:
        List of hit dicts.
    """
    if _BACKEND == "openobserve":
        from openobserve_client import query_openobserve

        return query_openobserve(sql, start_us, end_us)

    from duckdb_log_client import query

    return query(sql, start_us, end_us)


def datetime_to_us(dt) -> int:
    """Convert a datetime to microseconds since epoch."""
    return int(dt.timestamp() * 1_000_000)


def now_us() -> int:
    """Current time in microseconds since epoch."""
    from datetime import datetime, timezone

    return datetime_to_us(datetime.now(timezone.utc))
