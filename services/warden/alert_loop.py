"""Alert evaluation loop: check OpenObserve for DLP violations and push to CP."""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Optional

import requests
from constants import (
    ALERT_CHECK_INTERVAL,
    CONTROL_PLANE_TOKEN,
    DATA_PLANE_DIR,
    DATAPLANE_MODE,
    HEARTBEAT_URL,
)

logger = logging.getLogger(__name__)

# Microsecond timestamp of the last successful alert check.
_last_alert_check_us: int = 0


def _query_oo_alerts(sql: str, start_us: int, end_us: int) -> list[dict]:
    """Query OpenObserve for alert data.  Returns [] on any failure."""
    try:
        from openobserve_client import query_openobserve
        return query_openobserve(sql, start_us, end_us)
    except ImportError:
        return []
    except Exception as e:
        logger.warning("Alert OO query failed: %s", e)
        return []


def alert_loop(stop_event: Optional[threading.Event] = None):
    """Check OpenObserve for DLP violations and push alerts to the CP.

    Runs independently from the heartbeat loop in its own thread.
    Only active in connected mode with a valid CP token.
    """
    global _last_alert_check_us

    if DATAPLANE_MODE != "connected" or not CONTROL_PLANE_TOKEN:
        logger.info("Alert loop disabled (not in connected mode or no CP token)")
        return

    logger.info(
        "Alert loop starting (interval=%ds, heartbeat_url=%s)",
        ALERT_CHECK_INTERVAL,
        HEARTBEAT_URL,
    )

    # Start from 60 minutes ago on first run
    _last_alert_check_us = int((time.time() - 3600) * 1_000_000)

    _alerts_path = Path(DATA_PLANE_DIR) / "configs" / "alerts.json"
    if not _alerts_path.exists():
        _alerts_path = Path(__file__).resolve().parents[2] / "configs" / "alerts.json"
    alert_registry: dict = json.loads(_alerts_path.read_text())

    while not (stop_event and stop_event.is_set()):
        try:
            now_us = int(time.time() * 1_000_000)
            alerts: list[dict] = []

            for alert_id, alert_def in alert_registry.items():
                sql = alert_def["sql"].format(last_check_us=_last_alert_check_us)
                rows = _query_oo_alerts(sql, _last_alert_check_us, now_us)
                if not rows:
                    continue

                for row in rows:
                    alerts.append({
                        "event_type": alert_def["event_type"],
                        "severity": alert_def.get("severity", "info"),
                        "title": alert_def["title"].format(**row),
                        "message": alert_def["message"].format(**row),
                        "metadata": row,
                    })

            if alerts:
                try:
                    resp = requests.post(
                        f"{HEARTBEAT_URL}/api/v1/cell/alerts",
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

            _last_alert_check_us = now_us

        except Exception:
            logger.exception("Error in alert loop cycle")

        if stop_event:
            stop_event.wait(ALERT_CHECK_INTERVAL)
        else:
            time.sleep(ALERT_CHECK_INTERVAL)
