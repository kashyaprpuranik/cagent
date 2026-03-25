"""DuckDB-based log query client for lightweight mode.

Reads NDJSON log files written by Vector (file_backup sink) and executes
SQL queries using DuckDB's read_json_auto(). Drop-in replacement for
openobserve_client.py when the auditing profile (OpenObserve) is not active.

Log files are stored at /var/log/vector/backup/YYYY-MM-DD.log (one per day).
"""

import glob
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_LOG_DIR = os.environ.get("LOG_BACKUP_DIR", "/var/log/vector/backup")
_RETENTION_DAYS = int(os.environ.get("LOG_RETENTION_DAYS", "30"))


def is_healthy() -> bool:
    """DuckDB is always available (embedded)."""
    return os.path.isdir(_LOG_DIR)


def _log_files_for_range(start_us: int, end_us: int) -> list[str]:
    """Return log file paths that overlap with the given time range."""
    start_date = datetime.fromtimestamp(start_us / 1_000_000, tz=timezone.utc).strftime("%Y-%m-%d")
    end_date = datetime.fromtimestamp(end_us / 1_000_000, tz=timezone.utc).strftime("%Y-%m-%d")

    all_files = sorted(glob.glob(os.path.join(_LOG_DIR, "*.log")))
    matching = []
    for f in all_files:
        basename = os.path.basename(f).replace(".log", "")
        if start_date <= basename <= end_date:
            matching.append(f)
    return matching


def query(sql: str, start_us: int, end_us: int) -> list[dict]:
    """Execute a SQL query against NDJSON log files using DuckDB.

    The SQL should reference "cagent_logs" as the table name — this function
    replaces it with a read_json_auto() call over the matching files.

    Args:
        sql: SQL query (same format as OpenObserve queries).
        start_us: Start time in microseconds since epoch.
        end_us: End time in microseconds since epoch.

    Returns:
        List of result dicts (same format as openobserve_client.query_openobserve).
    """
    try:
        import duckdb
    except ImportError:
        logger.warning("duckdb not installed, returning empty results")
        return []

    files = _log_files_for_range(start_us, end_us)
    if not files:
        return []

    # Build the file source — DuckDB reads NDJSON with read_json_auto.
    # Wrap in a subquery that aliases `timestamp` → `_timestamp` (as microseconds)
    # to match OpenObserve's field naming convention used in widget SQL.
    file_list = ", ".join(f"'{f}'" for f in files)
    source = (
        f"(SELECT *, epoch_us(timestamp::TIMESTAMPTZ) AS _timestamp "
        f"FROM read_json_auto([{file_list}], format='newline_delimited', ignore_errors=true))"
    )

    # Replace table name with file source.
    # OO queries use FROM "cagent_logs" — handle both quoted and unquoted.
    adapted_sql = sql.replace('"cagent_logs"', source).replace("'cagent_logs'", source)

    # Add time range filter. OO handles this via start_time/end_time params;
    # DuckDB needs it in the WHERE clause.
    # Search for WHERE/GROUP BY/ORDER BY/LIMIT only AFTER the FROM source
    # (to avoid matching keywords inside read_json_auto parameters).
    upper = adapted_sql.upper()
    from_idx = upper.find("FROM ")
    # Skip past the read_json_auto(...) call by finding its closing paren
    paren_start = adapted_sql.find("(", from_idx)
    if paren_start != -1:
        depth = 1
        scan = paren_start + 1
        while scan < len(adapted_sql) and depth > 0:
            if adapted_sql[scan] == "(":
                depth += 1
            elif adapted_sql[scan] == ")":
                depth -= 1
            scan += 1
        clause_start = scan  # position after read_json_auto(...)
    else:
        clause_start = from_idx + 5

    rest = adapted_sql[clause_start:]
    rest_upper = rest.upper()
    time_filter = f"_timestamp >= {start_us} AND _timestamp <= {end_us}"

    where_pos = rest_upper.find("WHERE")
    if where_pos != -1:
        # Insert time filter after existing WHERE
        abs_pos = clause_start + where_pos + 5
        adapted_sql = adapted_sql[:abs_pos] + f" {time_filter} AND" + adapted_sql[abs_pos:]
    else:
        # Insert WHERE before GROUP BY, ORDER BY, or LIMIT
        insert_pos = len(rest)
        for kw in ["GROUP BY", "ORDER BY", "LIMIT"]:
            idx = rest_upper.find(kw)
            if idx != -1 and idx < insert_pos:
                insert_pos = idx
        abs_pos = clause_start + insert_pos
        adapted_sql = adapted_sql[:abs_pos] + f" WHERE {time_filter} " + adapted_sql[abs_pos:]

    try:
        conn = duckdb.connect(":memory:")
        result = conn.execute(adapted_sql)
        columns = [desc[0] for desc in result.description]
        rows = result.fetchall()
        conn.close()
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        logger.warning("DuckDB query failed: %s\nSQL: %s", e, adapted_sql[:500])
        return []


def datetime_to_us(dt: datetime) -> int:
    """Convert a datetime to microseconds since epoch."""
    return int(dt.timestamp() * 1_000_000)


def now_us() -> int:
    """Current time in microseconds since epoch."""
    return datetime_to_us(datetime.now(timezone.utc))


def cleanup_old_files() -> int:
    """Delete log files older than retention period. Returns count of files deleted."""
    if not os.path.isdir(_LOG_DIR):
        return 0

    from datetime import timedelta

    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)).strftime("%Y-%m-%d")

    deleted = 0
    for f in glob.glob(os.path.join(_LOG_DIR, "*.log")):
        basename = os.path.basename(f).replace(".log", "")
        if basename < cutoff_date:
            try:
                os.remove(f)
                deleted += 1
                logger.info("Deleted old log file: %s", f)
            except OSError as e:
                logger.warning("Failed to delete %s: %s", f, e)
    return deleted
