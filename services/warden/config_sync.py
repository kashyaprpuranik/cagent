"""Config sync and regeneration logic.

Extracted from main.py so that routers (and main.py itself) can import
sync_config / regenerate_configs without circular imports.
"""

import hashlib
import logging
from typing import Optional

import docker
import requests
import yaml
from config_generator import ConfigGenerator
from constants import (
    CAGENT_CONFIG_PATH,
    CONTROL_PLANE_TOKEN,
    CONTROL_PLANE_URL,
    COREDNS_CONTAINER_NAME,
    COREDNS_COREFILE_PATH,
    DATAPLANE_MODE,
    DLP_CONFIG_PATH,
    EMAIL_CONFIG_PATH,
    ENVOY_CONFIG_PATH,
    ENVOY_CONTAINER_NAME,
    MITM_PROXY_CONTAINER_NAME,
    DATA_PLANE_DIR,
    docker_client,
)
import os

logger = logging.getLogger(__name__)

# Path to .env file for docker-compose resource overrides
ENV_FILE_PATH = os.path.join(DATA_PLANE_DIR, ".env")

# Config generator instance (shared with main.py via this module)
config_generator = ConfigGenerator(CAGENT_CONFIG_PATH, mode=DATAPLANE_MODE)

# Synced domain policies with credentials (populated by sync_config in connected mode)
_synced_domain_policies: list[dict] = []


def get_synced_domain_policies() -> list[dict]:
    """Return the last-synced domain policies (including credentials)."""
    return _synced_domain_policies


# ---------------------------------------------------------------------------
# Service restart helpers
# ---------------------------------------------------------------------------


def restart_coredns():
    """Restart CoreDNS container to pick up new config."""
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        container.restart(timeout=10)
        logger.info("Restarted CoreDNS to apply new config")
        return True
    except docker.errors.NotFound:
        logger.warning(f"CoreDNS container '{COREDNS_CONTAINER_NAME}' not found")
        return False
    except Exception as e:
        logger.error(f"Failed to restart CoreDNS: {e}")
        return False


def reload_envoy():
    """Reload Envoy by restarting the container."""
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
        container.restart(timeout=5)
        logger.info("Restarted Envoy to apply new config")
        return True
    except docker.errors.NotFound:
        logger.warning(f"Envoy container '{ENVOY_CONTAINER_NAME}' not found")
        return False
    except Exception as e:
        logger.error(f"Failed to restart Envoy: {e}")
        return False


def reload_email_proxy():
    """Tell email-proxy to reload its config from disk."""
    try:
        resp = requests.post("http://10.200.2.40:8025/reload", timeout=5)
        if resp.status_code == 200:
            logger.info("Email-proxy reloaded config: %s", resp.json())
            return True
        logger.warning("Email-proxy reload returned %s", resp.status_code)
        return False
    except requests.exceptions.ConnectionError:
        logger.debug("Email-proxy not reachable (not running)")
        return False
    except Exception as e:
        logger.error(f"Failed to reload email-proxy: {e}")
        return False


def restart_mitm_proxy():
    """Restart mitm-proxy container to pick up new DLP config."""
    try:
        container = docker_client.containers.get(MITM_PROXY_CONTAINER_NAME)
        container.restart(timeout=10)
        logger.info("Restarted mitm-proxy to apply new DLP config")
        return True
    except docker.errors.NotFound:
        logger.debug(f"MITM-proxy container '{MITM_PROXY_CONTAINER_NAME}' not found (not running)")
        return False
    except Exception as e:
        logger.error(f"Failed to restart mitm-proxy: {e}")
        return False


# ---------------------------------------------------------------------------
# Config state tracking
# ---------------------------------------------------------------------------


def _stable_hash(content: str) -> str:
    """Hash content after stripping auto-generated timestamp lines."""
    stable = "\n".join(line for line in content.splitlines() if "Generated:" not in line)
    return hashlib.md5(stable.encode()).hexdigest()


class ConfigState:
    """Track last-written config hashes to avoid unnecessary restarts.

    Encapsulated in a class instead of bare module globals so there is a
    single, obvious mutation point and no ``global`` statements needed.
    """

    def __init__(self):
        self.envoy_hash: Optional[str] = None
        self.corefile_hash: Optional[str] = None
        self.email_hash: Optional[str] = None
        self.dlp_hash: Optional[str] = None
        self.last_policy_version: Optional[int] = None
        self.domain_policy_hash: Optional[str] = None


config_state = ConfigState()


# ---------------------------------------------------------------------------
# Config regeneration
# ---------------------------------------------------------------------------


def regenerate_configs(
    additional_domains: list = None,
    additional_email_accounts: list = None,
    additional_dlp_config: dict = None,
) -> bool:
    """Regenerate CoreDNS, Envoy, email, and DLP configs from cagent.yaml.

    Args:
        additional_domains: Extra domain entries to merge (e.g., from control plane sync).
            Each entry is a dict with at least 'domain' key, matching cagent.yaml format.
        additional_email_accounts: Extra email account entries to merge (e.g., from CP sync).
            Each entry is a dict matching cagent.yaml email account format.
        additional_dlp_config: CP-provided DLP config.  When set, fully replaces local config.

    Returns:
        True if configs were regenerated, False otherwise.
    """
    try:
        config_changed = config_generator.load_config()
        config_generator.set_additional_domains(additional_domains or [])
        config_generator.set_additional_email_accounts(additional_email_accounts or [])
        config_generator.set_additional_dlp_config(additional_dlp_config)

        # Generate configs and compute stable hashes (ignoring timestamps)
        corefile_content = config_generator.generate_corefile()
        envoy_config = config_generator.generate_envoy_config()
        envoy_yaml = yaml.dump(envoy_config, default_flow_style=False, sort_keys=False)
        email_config = config_generator.generate_email_config()
        dlp_config = config_generator.generate_dlp_config()

        corefile_hash = _stable_hash(corefile_content)
        envoy_hash = _stable_hash(envoy_yaml)
        email_hash = _stable_hash(email_config)
        dlp_hash = _stable_hash(dlp_config)

        corefile_changed = corefile_hash != config_state.corefile_hash
        envoy_changed = envoy_hash != config_state.envoy_hash
        email_changed = email_hash != config_state.email_hash
        dlp_changed = dlp_hash != config_state.dlp_hash

        if corefile_changed:
            config_generator.write_corefile(COREDNS_COREFILE_PATH)
            # CoreDNS auto-reloads via the `reload` plugin — no restart needed
            config_state.corefile_hash = corefile_hash

        if envoy_changed:
            config_generator.write_envoy_config(ENVOY_CONFIG_PATH)
            reload_envoy()
            config_state.envoy_hash = envoy_hash

        if email_changed:
            config_generator.write_email_config(EMAIL_CONFIG_PATH)
            reload_email_proxy()
            config_state.email_hash = email_hash

        if dlp_changed:
            config_generator.write_dlp_config(DLP_CONFIG_PATH)
            restart_mitm_proxy()
            config_state.dlp_hash = dlp_hash

        # Always update resource env vars when config changes
        if config_changed:
            config_generator.write_resource_env(ENV_FILE_PATH)

        if corefile_changed or envoy_changed or email_changed or dlp_changed:
            logger.info("Regenerated configs from cagent.yaml")
            # Invalidate domain policy caches only when domain configs changed
            domain_configs_changed = corefile_changed or envoy_changed
            if domain_configs_changed:
                from routers.domain_policy import invalidate_cache
                from routers.ext_authz import invalidate_cache as invalidate_ext_authz_cache

                invalidate_cache()
                invalidate_ext_authz_cache()
            return True
        else:
            logger.debug("Generated configs unchanged, skipping restart")
            return False

    except Exception as e:
        logger.error(f"Error regenerating configs: {e}")
        return False


# ---------------------------------------------------------------------------
# CP policy converters
# ---------------------------------------------------------------------------


def _cp_policy_to_domain_entry(policy: dict) -> dict:
    """Convert a CP domain policy response to a cagent.yaml domain entry."""
    entry = {"domain": policy["domain"]}
    if policy.get("alias"):
        entry["alias"] = policy["alias"]
    if policy.get("allowed_paths"):
        entry["allowed_paths"] = policy["allowed_paths"]
    if policy.get("requests_per_minute") is not None:
        entry.setdefault("rate_limit", {})["requests_per_minute"] = policy["requests_per_minute"]
    if policy.get("burst_size") is not None:
        entry.setdefault("rate_limit", {})["burst_size"] = policy["burst_size"]
    if policy.get("timeout"):
        entry["timeout"] = policy["timeout"]
    if policy.get("read_only"):
        entry["read_only"] = True
    # Note: credentials are NOT included — ext_authz handles them dynamically
    return entry


def _cp_dlp_policy_to_config(policy: dict) -> dict:
    """Convert a CP DLP policy response to a local dlp_config.json format."""
    config: dict = {}
    if "enabled" in policy:
        config["enabled"] = bool(policy["enabled"])
    if "mode" in policy:
        config["mode"] = policy["mode"] if policy["mode"] in ("log", "block", "redact") else "log"
    if "skip_domains" in policy:
        config["skip_domains"] = list(policy["skip_domains"])
    if "custom_patterns" in policy:
        config["custom_patterns"] = list(policy["custom_patterns"])
    return config


def _cp_email_policy_to_account_entry(policy: dict) -> dict:
    """Convert a CP email policy response (with credentials) to a cagent.yaml email account entry."""
    entry = {
        "name": policy["name"],
        "provider": policy["provider"],
        "email": policy["email"],
    }
    if policy.get("imap_server"):
        entry["imap_server"] = policy["imap_server"]
    if policy.get("imap_port"):
        entry["imap_port"] = policy["imap_port"]
    if policy.get("smtp_server"):
        entry["smtp_server"] = policy["smtp_server"]
    if policy.get("smtp_port"):
        entry["smtp_port"] = policy["smtp_port"]

    # Include credential directly (not env var refs — CP provides actual values)
    if policy.get("credential"):
        entry["credential"] = policy["credential"]

    # Policy settings
    entry["policy"] = {}
    if policy.get("allowed_recipients"):
        entry["policy"]["allowed_recipients"] = policy["allowed_recipients"]
    if policy.get("allowed_senders"):
        entry["policy"]["allowed_senders"] = policy["allowed_senders"]
    if policy.get("sends_per_hour") is not None:
        entry["policy"]["sends_per_hour"] = policy["sends_per_hour"]
    if policy.get("reads_per_hour") is not None:
        entry["policy"]["reads_per_hour"] = policy["reads_per_hour"]
    if not entry["policy"]:
        del entry["policy"]

    return entry


# ---------------------------------------------------------------------------
# Sync config (main entry point)
# ---------------------------------------------------------------------------


def sync_config() -> bool:
    """Sync configuration and regenerate CoreDNS, Envoy, and email configs.

    In standalone mode: regenerates from cagent.yaml only
    In connected mode: fetches domain + email policies from CP, merges with cagent.yaml

    Returns True if configs were updated, False otherwise.
    """
    if DATAPLANE_MODE == "standalone":
        # Standalone mode: just use cagent.yaml
        return regenerate_configs()

    # Connected mode: fetch from control plane and merge
    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        logger.warning("Control plane not configured, falling back to cagent.yaml")
        return regenerate_configs()

    global _synced_domain_policies

    cp_domain_entries = []
    cp_email_entries = []
    cp_dlp_config = None
    headers = {"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"}

    try:
        # Fetch domain policies with credentials for local ext_authz lookups
        response = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/domain-policies",
            params={"include_credentials": "true"},
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            policies = data.get("items", data) if isinstance(data, dict) else data
            # Store full policies (with credentials) for local ext_authz lookups
            _synced_domain_policies = [p for p in policies if p.get("enabled", True)]
            cp_domain_entries = [_cp_policy_to_domain_entry(p) for p in _synced_domain_policies]
            logger.info(f"Fetched {len(cp_domain_entries)} domain policies from control plane")
        else:
            logger.warning(f"Failed to fetch domain policies: {response.status_code}")

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not fetch domain policies: {e}")

    try:
        # Fetch email policies with credentials (requires agent token)
        response = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/email-policies?include_credentials=true",
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            policies = response.json()
            if isinstance(policies, dict):
                policies = policies.get("items", [])
            cp_email_entries = [_cp_email_policy_to_account_entry(p) for p in policies if p.get("enabled", True)]
            logger.info(f"Fetched {len(cp_email_entries)} email policies from control plane")
        else:
            logger.warning(f"Failed to fetch email policies: {response.status_code}")

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not fetch email policies: {e}")
    except Exception as e:
        logger.error(f"Error parsing email policies: {e}")

    try:
        # Fetch DLP policy from control plane
        response = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/dlp-policies",
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            policy = response.json()
            cp_dlp_config = _cp_dlp_policy_to_config(policy)
            logger.info("Fetched DLP policy from control plane")
        else:
            logger.warning(f"Failed to fetch DLP policy: {response.status_code}")

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not fetch DLP policy: {e}")
    except Exception as e:
        logger.error(f"Error parsing DLP policy: {e}")

    try:
        return regenerate_configs(
            additional_domains=cp_domain_entries,
            additional_email_accounts=cp_email_entries,
            additional_dlp_config=cp_dlp_config,
        )
    except Exception as e:
        logger.error(f"Error syncing config: {e}")
        return False
