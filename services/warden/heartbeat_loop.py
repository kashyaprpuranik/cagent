"""Heartbeat loop: send heartbeats, handle commands, sync config."""

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import requests
import runtime_config
import yaml
from config_sync import (
    _atomic_write,
    config_generator,
    config_state,
    reload_envoy,
    restart_coredns,
    sync_config,
    _stable_hash,
    ENV_FILE_PATH,
)
from constants import (
    CAGENT_CONFIG_PATH,
    CELL_LABEL,
    CONFIG_SYNC_INTERVAL,
    CONTROL_PLANE_TOKEN,
    CONTROL_PLANE_URL,
    COREDNS_COREFILE_PATH,
    DATAPLANE_MODE,
    ENVOY_CDS_PATH,
    ENVOY_CONFIG_PATH,
    ENVOY_RDS_PATH,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_URL,
    MAX_HEARTBEAT_WORKERS,
    VALID_RUNTIME_POLICIES,
    discover_cell_containers,
)
from container_ops import (
    _docker_container_update,
    _get_current_policy_label,
    _get_current_resource_limits,
    _infra_containers_ready,
    execute_command,
    get_container_status,
    recreate_container_with_policy,
    update_container_resources,
)

logger = logging.getLogger(__name__)


def _resources_need_update(current: dict, desired_cpu, desired_mem, desired_pids) -> bool:
    """Return True if any desired resource limit differs from current."""
    if desired_cpu is not None and current["cpu_limit"] != desired_cpu:
        return True
    if desired_mem is not None and current["memory_limit_mb"] != desired_mem:
        return True
    if desired_pids is not None and current["pids_limit"] != desired_pids:
        return True
    return False

# Thread-safe command result tracking (written from ThreadPoolExecutor workers,
# read from the heartbeat sender on the next cycle).
_command_results_lock = threading.Lock()
_last_command_results: dict = {}

# Snapshot of original resource limits before profile-based updates,
# so we can restore them when the profile is unassigned.
# Maps container name → dict of original Docker API field values.
_container_original_resources: dict = {}


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


def _send_bare_heartbeat(cell_name: str, command: str, result: str, message: str, status: str = "removed"):
    """Send a heartbeat without a live container (e.g., after wipe/stop).

    Used to report command results immediately without waiting for the next
    heartbeat cycle.
    """
    if not HEARTBEAT_URL or not CONTROL_PLANE_TOKEN:
        return
    heartbeat = {
        "status": status,
        "last_command": command,
        "last_command_result": result,
        "last_command_message": message,
    }
    try:
        requests.post(
            f"{HEARTBEAT_URL}/api/v1/cell/heartbeat",
            json=heartbeat,
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10,
        )
    except Exception as e:
        logger.warning(f"Failed to send bare heartbeat for {cell_name}: {e}")


def send_heartbeat(container) -> Optional[dict]:
    """Send heartbeat for a single cell container to control plane.

    Returns the parsed response (may contain a pending command), or None.
    """
    if not HEARTBEAT_URL or not CONTROL_PLANE_TOKEN:
        logger.warning("Heartbeat URL or token not configured, skipping heartbeat")
        return None

    name = container.name
    status = get_container_status(container)

    # If the cell container is running but infra containers aren't ready yet,
    # report as provisioning so CP doesn't mark the cell online prematurely.
    if status["status"] == "running" and not _infra_containers_ready():
        logger.info(f"{name}: cell running but infra containers not ready, reporting provisioning")
        status["status"] = "provisioning"

    heartbeat = {
        "status": status["status"],
        "container_id": status["container_id"],
        "uptime_seconds": status["uptime_seconds"],
        "cpu_percent": status["cpu_percent"],
        "memory_mb": status["memory_mb"],
        "memory_limit_mb": status["memory_limit_mb"],
    }

    # Include last command result for this container if any
    with _command_results_lock:
        last_result = _last_command_results.get(name)
        if last_result and last_result["command"]:
            heartbeat["last_command"] = last_result["command"]
            heartbeat["last_command_result"] = last_result["result"]
            heartbeat["last_command_message"] = last_result["message"]
            # Clear after sending
            _last_command_results[name] = {"command": None, "result": None, "message": None}

    try:
        response = requests.post(
            f"{HEARTBEAT_URL}/api/v1/cell/heartbeat",
            json=heartbeat,
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10,
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code in (401, 403):
            logger.error(f"Authentication failed: {response.status_code}")
            return None
        else:
            logger.warning(f"Heartbeat for {name} failed: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not reach control plane: {e}")
        return None


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def _heartbeat_and_handle(container):
    """Send heartbeat for one container and execute any pending command.

    Runs inside a ThreadPoolExecutor — must be thread-safe.
    Commands take priority over seccomp updates — only one operation per cycle.
    Returns the policy_version from the heartbeat response (or None).
    """
    response = send_heartbeat(container)
    if not response:
        return None

    policy_version = response.get("policy_version")

    # Commands take priority — execute and return
    if response.get("command"):
        command = response["command"]
        cmd_args = response.get("command_args")
        logger.info(f"Received command for {container.name}: {command}")
        success, message = execute_command(command, container, cmd_args)
        result_str = "success" if success else "failed"
        with _command_results_lock:
            _last_command_results[container.name] = {
                "command": command,
                "result": result_str,
                "message": message,
            }
        logger.info(f"Command {command} on {container.name} {'succeeded' if success else 'failed'}: {message}")
        # Wipe removes the container, so it won't be discovered next cycle.
        # Stop leaves the container in "exited" state — next heartbeat cycle
        # would work but container.stop(timeout=10) can block for up to 10s,
        # making the round-trip too slow for tight e2e timeouts.
        # Send the result immediately via a bare heartbeat for both.
        if command == "wipe":
            _send_bare_heartbeat(container.name, command, result_str, message)
            with _command_results_lock:
                _last_command_results.pop(container.name, None)
        elif command == "stop":
            _send_bare_heartbeat(container.name, command, result_str, message, status="exited")
            with _command_results_lock:
                _last_command_results.pop(container.name, None)
        return policy_version

    # No command — check if runtime policy needs updating
    # Accept runtime_policy (new) or seccomp_profile (backward compat from old CPs)
    policy_changed = False
    desired_policy = response.get("runtime_policy") or response.get("seccomp_profile")
    if desired_policy and desired_policy in VALID_RUNTIME_POLICIES:
        current_label = _get_current_policy_label(container)
        # Skip unlabelled containers (existing deployments) and gVisor containers
        if current_label is not None and current_label != desired_policy:
            logger.info(f"Policy mismatch on {container.name}: current={current_label}, desired={desired_policy}")
            success, message = recreate_container_with_policy(container, desired_policy)
            policy_changed = True
            with _command_results_lock:
                _last_command_results[container.name] = {
                    "command": "policy_update",
                    "result": "success" if success else "failed",
                    "message": message,
                }

    # Check resource limits (skip if policy change just triggered a recreation)
    if not policy_changed:
        desired_cpu = response.get("cpu_limit")
        desired_mem = response.get("memory_limit_mb")
        desired_pids = response.get("pids_limit")

        if desired_cpu is not None or desired_mem is not None or desired_pids is not None:
            # Profile has resource limits — apply them
            current = _get_current_resource_limits(container)

            if _resources_need_update(current, desired_cpu, desired_mem, desired_pids):
                # Snapshot original values before first profile update
                if container.name not in _container_original_resources:
                    container.reload()
                    hc = container.attrs.get("HostConfig", {})
                    _container_original_resources[container.name] = {
                        "NanoCPUs": hc.get("NanoCpus", 0) or 0,
                        "Memory": hc.get("Memory", 0) or 0,
                        "MemorySwap": hc.get("MemorySwap", 0) or 0,
                        "PidsLimit": hc.get("PidsLimit", 0) or 0,
                    }

                success, message = update_container_resources(
                    container,
                    cpu_limit=desired_cpu,
                    memory_limit_mb=desired_mem,
                    pids_limit=desired_pids,
                )
                with _command_results_lock:
                    _last_command_results[container.name] = {
                        "command": "resource_update",
                        "result": "success" if success else "failed",
                        "message": message,
                    }
        elif container.name in _container_original_resources:
            # Profile unassigned — restore original resource limits.
            # Docker's update API ignores NanoCPUs=0, so we must restore
            # the original value (e.g. the compose-defined CPU limit).
            restore_data = _container_original_resources[container.name]
            logger.info(f"Restoring resource limits on {container.name}: {restore_data}")
            _docker_container_update(container, restore_data)
            _container_original_resources.pop(container.name, None)

    return policy_version


def _check_standalone_config(agents):
    """In standalone mode, check runtime policy and resource limits from cagent.yaml.

    Reads the config file once and applies both policy and resource checks.
    """
    try:
        config_path = Path(CAGENT_CONFIG_PATH)
        if not config_path.exists():
            return
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}

        # --- Runtime policy ---
        security = config.get("security", {})
        desired_policy = security.get("runtime_policy") or security.get("seccomp_profile", "hardened")
        if desired_policy in VALID_RUNTIME_POLICIES:
            for container in agents:
                current_label = _get_current_policy_label(container)
                if current_label is not None and current_label != desired_policy:
                    logger.info(
                        f"Standalone policy mismatch on {container.name}: "
                        f"current={current_label}, desired={desired_policy}"
                    )
                    recreate_container_with_policy(container, desired_policy)
        elif desired_policy:
            logger.warning(f"Invalid runtime_policy in cagent.yaml: {desired_policy}")

        # --- Resource limits ---
        resources = config.get("resources", {})
        if not resources:
            return
        desired_cpu = resources.get("cpu_limit")
        desired_mem = resources.get("memory_limit_mb")
        desired_pids = resources.get("pids_limit")
        if desired_cpu is None and desired_mem is None and desired_pids is None:
            return

        for container in agents:
            current = _get_current_resource_limits(container)
            needs_update = _resources_need_update(current, desired_cpu, desired_mem, desired_pids)
            if needs_update:
                update_container_resources(container, desired_cpu, desired_mem, desired_pids)
    except Exception as e:
        logger.error(f"Error checking standalone config: {e}")


def send_online_ping():
    """Notify the control plane that this data plane is online.

    POSTs to /api/v1/cell/online with retry logic:
    - 200: success, return immediately
    - 202: provisioner not ready yet, sleep retry_after seconds and retry
    - error/5xx: log warning, sleep 15s and retry
    - Give up after 15 minutes total
    """
    url = f"{CONTROL_PLANE_URL}/api/v1/cell/online"
    headers = {"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"}
    deadline = time.time() + 15 * 60  # 15 minutes

    logger.info("Sending online ping to %s", url)
    while time.time() < deadline:
        try:
            resp = requests.post(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                logger.info("Online ping accepted — provisioning complete")
                return
            elif resp.status_code == 202:
                retry_after = resp.json().get("retry_after", 15)
                logger.info("Online ping: provisioning pending, retrying in %ds", retry_after)
                time.sleep(retry_after)
            else:
                logger.warning("Online ping returned %d, retrying in 15s", resp.status_code)
                time.sleep(15)
        except Exception as e:
            logger.warning("Online ping failed: %s, retrying in 15s", e)
            time.sleep(15)

    logger.error("Online ping: gave up after 15 minutes — continuing to heartbeat loop")


def main_loop(stop_event: Optional[threading.Event] = None):
    """Main loop: discover agents, send heartbeats, execute commands, sync config."""
    logger.info("Warden polling loop starting")
    logger.info(f"  Mode: {DATAPLANE_MODE}")
    logger.info(f"  Config file: {CAGENT_CONFIG_PATH}")
    logger.info(f"  CoreDNS config: {COREDNS_COREFILE_PATH}")
    logger.info(f"  Envoy config: {ENVOY_CONFIG_PATH}")
    logger.info(f"  Cell discovery label: {CELL_LABEL}")
    logger.info(f"  Config sync interval: {CONFIG_SYNC_INTERVAL}s")

    if DATAPLANE_MODE == "connected":
        logger.info(f"  Control plane: {CONTROL_PLANE_URL}")
        if HEARTBEAT_URL != CONTROL_PLANE_URL:
            logger.info(f"  Heartbeat URL: {HEARTBEAT_URL}")
        logger.info(f"  Heartbeat interval: {HEARTBEAT_INTERVAL}s")
        if not CONTROL_PLANE_TOKEN:
            logger.warning("CONTROL_PLANE_TOKEN not set - heartbeats will fail")
    else:
        logger.info("  Running in standalone mode (no control plane sync)")

    # Log initially discovered agents
    agents = discover_cell_containers()
    logger.info(f"  Discovered {len(agents)} cell container(s): {[c.name for c in agents]}")

    # Initial config generation from cagent.yaml (always write on startup)
    # Uses xDS mode (bootstrap + CDS/RDS) consistent with regenerate_configs().
    logger.info("Generating initial configs from cagent.yaml...")
    config_generator.load_config()
    config_generator.write_corefile(COREDNS_COREFILE_PATH)
    # Write CDS + RDS before bootstrap so Envoy finds them on startup
    cds_yaml = yaml.dump(config_generator.generate_envoy_cds(), default_flow_style=False, sort_keys=False)
    _atomic_write(ENVOY_CDS_PATH, cds_yaml)
    rds_yaml = yaml.dump(config_generator.generate_envoy_rds(), default_flow_style=False, sort_keys=False)
    _atomic_write(ENVOY_RDS_PATH, rds_yaml)
    config_generator.write_envoy_bootstrap(ENVOY_CONFIG_PATH)
    config_generator.write_resource_env(ENV_FILE_PATH)
    restart_coredns()
    reload_envoy()
    # Snapshot current state so regenerate_configs() can detect changes
    config_state.corefile_hash = _stable_hash(config_generator.generate_corefile())
    bootstrap_yaml = yaml.dump(
        config_generator.generate_envoy_bootstrap(), default_flow_style=False, sort_keys=False
    )
    config_state.envoy_bootstrap_hash = _stable_hash(bootstrap_yaml)
    config_state.envoy_cds_hash = _stable_hash(cds_yaml)
    config_state.envoy_rds_hash = _stable_hash(rds_yaml)
    config_state.email_hash = _stable_hash(config_generator.generate_email_config())
    config_state.dlp_hash = _stable_hash(config_generator.generate_dlp_config())
    logger.info("Initial config generation complete")

    # Wait for infra containers before notifying CP that this DP is online
    if DATAPLANE_MODE == "connected" and CONTROL_PLANE_TOKEN:
        logger.info("Waiting for infra containers before sending online ping...")
        while not _infra_containers_ready():
            logger.info("Infra containers not ready yet, rechecking in 5s")
            time.sleep(5)
        logger.info("Infra containers ready")
        send_online_ping()

    # Use wall-clock monotonic time for config sync scheduling so that
    # slow heartbeat cycles (e.g. Docker stats across many containers)
    # don't cause sync drift.
    last_sync_time = time.monotonic()

    while not (stop_event and stop_event.is_set()):
        try:
            # Discover cell containers each cycle (handles containers
            # being added/removed at runtime)
            agents = discover_cell_containers()

            # In connected mode, send heartbeat and handle commands per cell (concurrent)
            policy_version = None
            if DATAPLANE_MODE == "connected" and CONTROL_PLANE_TOKEN:
                workers = min(MAX_HEARTBEAT_WORKERS, len(agents)) if agents else 1
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(_heartbeat_and_handle, c): c for c in agents}
                    for f in as_completed(futures):
                        try:
                            pv = f.result()
                            # Use the first non-None policy_version (all cells in
                            # the same tenant share the same version).
                            if pv is not None and policy_version is None:
                                policy_version = pv
                        except Exception as exc:
                            container = futures[f]
                            logger.error(f"Heartbeat failed for {container.name}: {exc}")

            # Version-driven config sync: only fetch policies when CP signals a change
            now = time.monotonic()
            sync_interval = int(runtime_config.get("CONFIG_SYNC_INTERVAL", CONFIG_SYNC_INTERVAL))
            if policy_version is None:
                # No Redis on CP or old CP — fall back to interval polling
                if (now - last_sync_time) >= sync_interval:
                    sync_config()
                    last_sync_time = now
            elif policy_version != config_state.last_policy_version:
                logger.info(
                    f"Policy version changed: {config_state.last_policy_version} -> {policy_version}, syncing config"
                )
                sync_config()
                # Update last_policy_version ONLY after sync_config succeeds
                # (configs written and services restarted).  If sync_config
                # raises, the version stays stale and we retry next heartbeat.
                config_state.last_policy_version = policy_version
                last_sync_time = now

            # Standalone mode: check runtime policy and resource limits from cagent.yaml
            if DATAPLANE_MODE == "standalone" and agents:
                _check_standalone_config(agents)

        except Exception as e:
            logger.error(f"Error in main loop: {e}")

        # Wait for next cycle — re-read interval from runtime overrides
        interval = int(runtime_config.get("HEARTBEAT_INTERVAL", HEARTBEAT_INTERVAL))
        if stop_event:
            stop_event.wait(interval)
        else:
            time.sleep(interval)
