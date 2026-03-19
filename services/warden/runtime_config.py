"""Runtime config overrides — hot-updatable config pushed from CP.

Persists to a JSON file so values survive warden restarts.
Loaded lazily on each heartbeat cycle so changes take effect
without restarting warden.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Location: inside the mounted DP dir so it persists across container restarts.
# Override with RUNTIME_CONFIG_PATH for testing (avoids polluting the repo checkout).
_CONFIG_PATH = os.environ.get(
    "RUNTIME_CONFIG_PATH",
    os.path.join(os.environ.get("DATA_PLANE_DIR", "/app/cagent"), "runtime_config.json"),
)

# Allowlist of keys that can be hot-updated, with type and bounds
UPDATABLE_KEYS: dict[str, dict] = {
    "HEARTBEAT_INTERVAL": {"type": int, "min": 10, "max": 3600},
    "CONFIG_SYNC_INTERVAL": {"type": int, "min": 30, "max": 3600},
    "ALERT_CHECK_INTERVAL": {"type": int, "min": 10, "max": 600},
    "OPENOBSERVE_URL": {"type": str},
    "OPENOBSERVE_USER": {"type": str},
    "OPENOBSERVE_PASSWORD": {"type": str},
    "BETA_FEATURES": {"type": str},
    "SSH_AUTHORIZED_KEYS": {"type": str},
    "WARDEN_API_TOKEN": {"type": str},
    "WARDEN_TLS_CERT": {"type": str},
    "WARDEN_TLS_KEY": {"type": str},
    "WARDEN_MTLS_CA_CERT": {"type": str},
}


def load() -> dict:
    """Load runtime config overrides from disk. Returns empty dict if missing."""
    try:
        path = Path(_CONFIG_PATH)
        if path.exists():
            with open(path) as f:
                return json.load(f)
    except Exception as e:
        logger.warning("Failed to load runtime config: %s", e)
    return {}


def save(overrides: dict) -> None:
    """Atomically write runtime config overrides to disk."""
    path = Path(_CONFIG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(overrides, indent=2))
    tmp.rename(path)
    logger.info("Runtime config saved: %s", list(overrides.keys()))


def get(key: str, default: Any = None) -> Any:
    """Get a runtime config value, falling back to env var, then default."""
    overrides = load()
    if key in overrides:
        return overrides[key]
    env_val = os.environ.get(key)
    if env_val is not None:
        return env_val
    return default


def validate_and_merge(updates: dict) -> tuple[dict, list[str]]:
    """Validate incoming updates against the allowlist.

    Returns (applied: dict, rejected: list of reasons).
    """
    current = load()
    applied = {}
    rejected = []

    for key, value in updates.items():
        if key not in UPDATABLE_KEYS:
            rejected.append(f"{key}: not in allowlist")
            continue

        spec = UPDATABLE_KEYS[key]
        expected_type = spec["type"]

        # Type coercion
        try:
            value = expected_type(value)
        except (ValueError, TypeError):
            rejected.append(f"{key}: expected {expected_type.__name__}, got {type(value).__name__}")
            continue

        # Bounds check for numeric types
        if expected_type in (int, float):
            min_val = spec.get("min")
            max_val = spec.get("max")
            if min_val is not None and value < min_val:
                rejected.append(f"{key}: {value} < min {min_val}")
                continue
            if max_val is not None and value > max_val:
                rejected.append(f"{key}: {value} > max {max_val}")
                continue

        current[key] = value
        applied[key] = value

    if applied:
        save(current)

    return applied, rejected
