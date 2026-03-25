"""Alert evaluation loop: check VictoriaLogs for DLP violations and push to CP."""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from constants import (
    ALERT_CHECK_INTERVAL,
    CONTROL_PLANE_TOKEN,
    CONTROL_PLANE_URL,
    DATA_PLANE_DIR,
    DATAPLANE_MODE,
)

logger = logging.getLogger(__name__)

# ISO8601 timestamp of the last successful alert check.
_last_alert_check_iso: str = ""


def _query_vl_alerts(logsql: str, start_us: int, end_us: int) -> list[dict]:
    """Query VictoriaLogs for alert data.  Returns [] on any failure."""
    try:
        from victorialogs_client import query_stats

        return query_stats(logsql, start_us, end_us)
    except ImportError:
        return []
    except Exception as e:
        logger.warning("Alert VL query failed: %s", e)
        return []


def alert_loop(stop_event: Optional[threading.Event] = None):
    """Check VictoriaLogs for DLP violations and push alerts to the CP.

    Runs independently from the heartbeat loop in its own thread.
    Only active in connected mode with a valid CP token.
    """
    global _last_alert_check_iso

    if DATAPLANE_MODE != "connected" or not CONTROL_PLANE_TOKEN:
        logger.info("Alert loop disabled (not in connected mode or no CP token)")
        return

    logger.info(
        "Alert loop starting (interval=%ds, heartbeat_url=%s)",
        ALERT_CHECK_INTERVAL,
        CONTROL_PLANE_URL,
    )

    # Start from 60 minutes ago on first run
    _last_alert_check_iso = datetime.fromtimestamp(time.time() - 3600, tz=timezone.utc).isoformat()

    _alerts_path = Path(DATA_PLANE_DIR) / "configs" / "alerts.json"
    if not _alerts_path.exists():
        _alerts_path = Path(__file__).resolve().parents[2] / "configs" / "alerts.json"
    alert_registry: dict = json.loads(_alerts_path.read_text())

    while not (stop_event and stop_event.is_set()):
        try:
            now_us = int(time.time() * 1_000_000)
            start_us = int(datetime.fromisoformat(_last_alert_check_iso).timestamp() * 1_000_000)
            alerts: list[dict] = []

            for alert_id, alert_def in alert_registry.items():
                logsql = alert_def["logsql"].format(last_check_iso=_last_alert_check_iso)
                rows = _query_vl_alerts(logsql, start_us, now_us)
                if not rows:
                    continue

                for row in rows:
                    alerts.append(
                        {
                            "event_type": alert_def["event_type"],
                            "severity": alert_def.get("severity", "info"),
                            "title": alert_def["title"].format(**row),
                            "message": alert_def["message"].format(**row),
                            "metadata": row,
                        }
                    )

            if alerts:
                try:
                    resp = requests.post(
                        f"{CONTROL_PLANE_URL}/api/v1/cell/alerts",
                        json={"alerts": alerts},
                        headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
                        timeout=10,
                    )
                    if resp.status_code < 300:
                        logger.info("Pushed %d alert(s) to CP", len(alerts))
                    else:
                        logger.warning(
                            "CP alert push failed: %s %s",
                            resp.status_code,
                            resp.text[:200],
                        )
                except requests.exceptions.RequestException as e:
                    logger.warning("CP alert push error: %s", e)

            _last_alert_check_iso = datetime.fromtimestamp(now_us / 1_000_000, tz=timezone.utc).isoformat()

        except Exception:
            logger.exception("Error in alert loop cycle")

        if stop_event:
            stop_event.wait(ALERT_CHECK_INTERVAL)
        else:
            time.sleep(ALERT_CHECK_INTERVAL)
