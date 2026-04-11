"""Config sync and regeneration logic.

Extracted from main.py so that routers (and main.py itself) can import
sync_config / regenerate_configs without circular imports.
"""

import hashlib
import logging
import os
import threading
from pathlib import Path
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
    DATA_PLANE_DIR,
    DATAPLANE_MODE,
    DLP_CONFIG_PATH,
    EMAIL_CONFIG_PATH,
    ENVOY_CDS_PATH,
    ENVOY_CONFIG_PATH,
    ENVOY_CONTAINER_NAME,
    ENVOY_RDS_PATH,
    docker_client,
)

logger = logging.getLogger(__name__)
_NET_OCTET = os.environ.get("NET_OCTET", "200")

# Proxy mode: "legacy" (Envoy+mitmproxy+CoreDNS) or "rust" (cagent-proxy)
PROXY_MODE = os.environ.get("PROXY_MODE", "legacy")
CAGENT_PROXY_URL = os.environ.get("CAGENT_PROXY_URL", f"http://10.{_NET_OCTET}.2.20:18080")
# Shared secret for authenticated POST /config to cagent-proxy.  Must match
# the CAGENT_PROXY_TOKEN env var on the cagent-proxy container.  Empty in
# dev/standalone — cagent-proxy logs a warning on startup when unset.
CAGENT_PROXY_TOKEN = os.environ.get("CAGENT_PROXY_TOKEN", "")

# Path to .env file for docker-compose resource overrides
ENV_FILE_PATH = os.path.join(DATA_PLANE_DIR, ".env")

# Config generator instance (shared with main.py via this module)
config_generator = ConfigGenerator(CAGENT_CONFIG_PATH, mode=DATAPLANE_MODE)

# Synced domain policies with credentials (populated by sync_config in connected mode)
_synced_domain_policies: list[dict] = []

# Lock to prevent concurrent config syncs.  sync_config() is called from
# the heartbeat thread (on policy_version change) and the /config/sync API
# endpoint (uvicorn thread).  Without this lock, concurrent calls race on
# _atomic_write temp files (cds.tmp, rds.tmp) and corrupt each other.
_sync_lock = threading.Lock()


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
    """Tell email-proxy to reload its config from disk.

    In rust mode the legacy email-proxy container is not running —
    cagent-proxy handles email natively via the config push payload.
    Skip the HTTP /reload call and return True as a no-op.
    """
    if PROXY_MODE == "rust":
        logger.debug("rust mode: email handled in-process by cagent-proxy, no reload needed")
        return True
    try:
        resp = requests.post(f"http://10.{_NET_OCTET}.2.40:8025/reload", timeout=5)
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


def push_to_cagent_proxy(
    domain_entries: list,
    domain_policies: list,
    dlp_config: dict = None,
    email_accounts: list = None,
) -> bool:
    """Push config to cagent-proxy via its HTTP config API.

    Translates cagent.yaml-style domain entries + CP credential policies
    into the ProxyConfig JSON that cagent-proxy expects.

    `email_accounts` are forwarded as-is for the in-process IMAP/SMTP
    handler (replaces the legacy email-proxy container in rust mode).
    """
    # Build a credential lookup from CP domain policies
    cred_by_domain = {}
    for p in domain_policies:
        if p.get("credential_header") and p.get("credential_value"):
            cred_by_domain[p["domain"]] = p

    proxy_domains = []
    for entry in domain_entries:
        domain = entry.get("domain", "")
        pd = {
            "domain": domain,
            # tls defaults to True (HTTPS upstream); explicit `tls: false`
            # in cagent.yaml is for HTTP-only upstreams.
            "tls": bool(entry.get("tls", True)),
            "read_only": entry.get("read_only", False),
            "allowed_paths": entry.get("allowed_paths", []),
        }
        # Alias: creates {alias}.devbox.local shortcut
        if entry.get("alias"):
            pd["alias"] = entry["alias"]
        # Rate limit (rpm + optional explicit burst override)
        rl = entry.get("rate_limit", {})
        if rl.get("requests_per_minute"):
            pd["rate_limit_rpm"] = rl["requests_per_minute"]
        if rl.get("burst_size"):
            pd["burst_size"] = rl["burst_size"]
        # Per-domain upstream timeout (e.g. "30s", "120s", "5m")
        if entry.get("timeout"):
            pd["timeout"] = entry["timeout"]
        # Credentials from CP policies (injected in-process by cagent-proxy)
        cred = cred_by_domain.get(domain, {})
        if cred.get("credential_header"):
            pd["credential_header"] = cred["credential_header"]
        if cred.get("credential_format"):
            pd["credential_format"] = cred["credential_format"]
        if cred.get("credential_value"):
            pd["credential_value"] = cred["credential_value"]

        proxy_domains.append(pd)

    payload = {"domains": proxy_domains}

    # Include DLP config if available
    if dlp_config:
        payload["dlp"] = dlp_config

    # Include email accounts for the in-process IMAP/SMTP handler.
    # Only generic password-auth accounts are forwarded — Gmail/Outlook
    # OAuth2 accounts are skipped (not supported by cagent-proxy yet) and
    # logged for operator visibility.
    if email_accounts:
        proxy_email_accounts: list = []
        for acct in email_accounts:
            provider = (acct.get("provider") or "generic").lower()
            if provider != "generic":
                logger.warning(
                    "Skipping email account %r: provider %s not supported in rust proxy mode",
                    acct.get("name"),
                    provider,
                )
                continue
            cred = acct.get("credential") or {}
            password = cred.get("password", "")
            if not password:
                logger.warning(
                    "Skipping email account %r: no password credential",
                    acct.get("name"),
                )
                continue
            entry = {
                "name": acct.get("name", ""),
                "email": acct.get("email", ""),
                "imap_server": acct.get("imap_server", ""),
                "imap_port": acct.get("imap_port", 993),
                "smtp_server": acct.get("smtp_server", ""),
                "smtp_port": acct.get("smtp_port", 587),
                "credential": {
                    "password": password,
                    "smtp_username": cred.get("smtp_username", ""),
                },
            }
            policy = acct.get("policy") or {}
            if policy:
                entry["policy"] = {
                    "allowed_recipients": policy.get("allowed_recipients", ["*"]),
                    "allowed_senders": policy.get("allowed_senders", ["*"]),
                    "sends_per_hour": policy.get("sends_per_hour", 50),
                    "reads_per_hour": policy.get("reads_per_hour", 200),
                }
            proxy_email_accounts.append(entry)
        if proxy_email_accounts:
            payload["email_accounts"] = proxy_email_accounts

    headers = {}
    if CAGENT_PROXY_TOKEN:
        headers["X-Config-Token"] = CAGENT_PROXY_TOKEN

    try:
        resp = requests.post(
            f"{CAGENT_PROXY_URL}/config",
            json=payload,
            headers=headers,
            timeout=5,
        )
        if resp.status_code == 200:
            logger.info("Pushed config to cagent-proxy: %s", resp.json())
            return True
        if resp.status_code == 401:
            logger.error(
                "cagent-proxy rejected config push (401): CAGENT_PROXY_TOKEN "
                "missing or does not match the one set on cagent-proxy"
            )
            return False
        logger.warning("cagent-proxy config push returned %s: %s", resp.status_code, resp.text)
        return False
    except requests.exceptions.ConnectionError:
        logger.warning("cagent-proxy not reachable at %s", CAGENT_PROXY_URL)
        return False
    except Exception as e:
        logger.error("Failed to push config to cagent-proxy: %s", e)
        return False


def reload_mitm_proxy():
    """Trigger mitmproxy live-reload by touching the DLP addon script.

    mitmproxy's watchdog detects the mtime change on the -s script file
    and re-instantiates the addon, which re-reads dlp_config.json.
    """
    try:
        addon_path = Path(DLP_CONFIG_PATH).parent / "dlp_addon.py"
        addon_path.touch()
        logger.info("Touched %s to trigger mitmproxy live-reload", addon_path)
        return True
    except Exception as e:
        logger.error(f"Failed to touch DLP addon for reload: {e}")
        return False


# ---------------------------------------------------------------------------
# Atomic file writes (for Envoy xDS hot-reload via inotify)
# ---------------------------------------------------------------------------


def _atomic_write(path: str, content: str):
    """Write content atomically via rename for Envoy inotify-based xDS reload.

    Envoy's watched_directory triggers on MOVED_TO events.  Writing to a temp
    file then renaming ensures Envoy never reads a partially-written file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(content)
    tmp.rename(target)


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
        self.envoy_bootstrap_hash: Optional[str] = None
        self.envoy_cds_hash: Optional[str] = None
        self.envoy_rds_hash: Optional[str] = None
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
    if not _sync_lock.acquire(blocking=False):
        logger.debug("Config regeneration already in progress, skipping")
        return False
    try:
        config_changed = config_generator.load_config()
        config_generator.set_additional_domains(additional_domains or [])
        config_generator.set_additional_email_accounts(additional_email_accounts or [])
        config_generator.set_additional_dlp_config(additional_dlp_config)

        # Generate email/DLP configs (always needed regardless of proxy mode)
        email_config = config_generator.generate_email_config()
        dlp_config = config_generator.generate_dlp_config()
        email_hash = _stable_hash(email_config)
        dlp_hash = _stable_hash(dlp_config)
        email_changed = email_hash != config_state.email_hash
        dlp_changed = dlp_hash != config_state.dlp_hash

        if PROXY_MODE == "rust":
            # ── Rust proxy path: push config via HTTP instead of writing files ──
            all_domains = config_generator.get_domains()
            dlp = config_generator.get_dlp_config()
            all_email_accounts = config_generator.get_email_accounts()
            proxy_changed = push_to_cagent_proxy(
                all_domains,
                _synced_domain_policies,
                dlp_config=dlp,
                email_accounts=all_email_accounts,
            )
        else:
            # ── Legacy path: generate Corefile + Envoy xDS files ──
            corefile_content = config_generator.generate_corefile()
            bootstrap = config_generator.generate_envoy_bootstrap()
            bootstrap_yaml = yaml.dump(bootstrap, default_flow_style=False, sort_keys=False)
            cds = config_generator.generate_envoy_cds()
            cds_yaml = yaml.dump(cds, default_flow_style=False, sort_keys=False)
            rds = config_generator.generate_envoy_rds()
            rds_yaml = yaml.dump(rds, default_flow_style=False, sort_keys=False)

            corefile_hash = _stable_hash(corefile_content)
            bootstrap_hash = _stable_hash(bootstrap_yaml)
            cds_hash = _stable_hash(cds_yaml)
            rds_hash = _stable_hash(rds_yaml)

            corefile_changed = corefile_hash != config_state.corefile_hash
            bootstrap_changed = bootstrap_hash != config_state.envoy_bootstrap_hash
            cds_changed = cds_hash != config_state.envoy_cds_hash
            rds_changed = rds_hash != config_state.envoy_rds_hash

            if corefile_changed:
                config_generator.write_corefile(COREDNS_COREFILE_PATH)
                config_state.corefile_hash = corefile_hash

            if cds_changed:
                _atomic_write(ENVOY_CDS_PATH, cds_yaml)
                config_state.envoy_cds_hash = cds_hash

            if rds_changed:
                _atomic_write(ENVOY_RDS_PATH, rds_yaml)
                config_state.envoy_rds_hash = rds_hash

            if bootstrap_changed:
                config_generator.write_envoy_bootstrap(ENVOY_CONFIG_PATH)
                reload_envoy()
                config_state.envoy_bootstrap_hash = bootstrap_hash

            if dlp_changed:
                config_generator.write_dlp_config(DLP_CONFIG_PATH)
                reload_mitm_proxy()
                config_state.dlp_hash = dlp_hash

            proxy_changed = corefile_changed or cds_changed or rds_changed or bootstrap_changed

        if email_changed:
            config_generator.write_email_config(EMAIL_CONFIG_PATH)
            reload_email_proxy()
            config_state.email_hash = email_hash

        # Always update resource env vars when config changes
        if config_changed:
            config_generator.write_resource_env(ENV_FILE_PATH)

        any_changed = proxy_changed or email_changed or dlp_changed
        if any_changed:
            logger.info("Regenerated configs from cagent.yaml")
            if proxy_changed:
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
    finally:
        _sync_lock.release()


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
    # tls flag: HTTPS upstream is the default, only set if explicitly disabled
    if policy.get("tls") is False:
        entry["tls"] = False
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


def _fetch_cp_resource(path: str, label: str, params: dict = None) -> Optional[dict]:
    """Fetch a resource from the control plane API.

    Returns the parsed JSON on success, None on failure.
    """
    headers = {"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"}
    try:
        response = requests.get(
            f"{CONTROL_PLANE_URL}{path}",
            params=params,
            headers=headers,
            timeout=10,
        )
        if response.status_code == 200:
            return response.json()
        logger.warning(f"Failed to fetch {label}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not fetch {label}: {e}")
    except Exception as e:
        logger.error(f"Error parsing {label}: {e}")
    return None


def sync_config() -> bool:
    """Sync configuration and regenerate CoreDNS, Envoy, and email configs.

    In standalone mode: regenerates from cagent.yaml only
    In connected mode: fetches domain + email policies from CP, merges with cagent.yaml

    Returns True if configs were updated, False otherwise.
    """
    if DATAPLANE_MODE == "standalone":
        return regenerate_configs()

    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        logger.warning("Control plane not configured, falling back to cagent.yaml")
        return regenerate_configs()

    global _synced_domain_policies

    cp_domain_entries = []
    cp_email_entries = []
    cp_dlp_config = None

    # Fetch domain policies
    data = _fetch_cp_resource("/api/v1/domain-policies", "domain policies", params={"include_credentials": "true"})
    if data is not None:
        policies = data.get("items", data) if isinstance(data, dict) else data
        _synced_domain_policies = [p for p in policies if p.get("enabled", True)]
        cp_domain_entries = [_cp_policy_to_domain_entry(p) for p in _synced_domain_policies]
        logger.info(f"Fetched {len(cp_domain_entries)} domain policies from control plane")

    # Fetch email policies
    data = _fetch_cp_resource("/api/v1/email-policies", "email policies", params={"include_credentials": "true"})
    if data is not None:
        policies = data.get("items", []) if isinstance(data, dict) else data
        cp_email_entries = [_cp_email_policy_to_account_entry(p) for p in policies if p.get("enabled", True)]
        logger.info(f"Fetched {len(cp_email_entries)} email policies from control plane")

    # Fetch DLP policy
    data = _fetch_cp_resource("/api/v1/dlp-policies", "DLP policy")
    if data is not None:
        cp_dlp_config = _cp_dlp_policy_to_config(data)
        logger.info("Fetched DLP policy from control plane")

    try:
        return regenerate_configs(
            additional_domains=cp_domain_entries,
            additional_email_accounts=cp_email_entries,
            additional_dlp_config=cp_dlp_config,
        )
    except Exception as e:
        logger.error(f"Error syncing config: {e}")
        return False
