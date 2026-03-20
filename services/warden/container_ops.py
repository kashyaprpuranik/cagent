"""Container operations: seccomp profiles, resource limits, status, commands."""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import docker
import yaml
from constants import (
    COREDNS_CONTAINER_NAME,
    ENVOY_CONTAINER_NAME,
    MITM_PROXY_CONTAINER_NAME,
    RUNTIME_POLICIES,
    SECCOMP_PROFILES_DIR,
    VALID_RUNTIME_POLICIES,
    VALID_SECCOMP_PROFILES,
    discover_cell_containers,
    docker_client,
)
from utils import calculate_container_stats

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Seccomp profile management
# ---------------------------------------------------------------------------


def _load_seccomp_profile(name: str) -> dict:
    """Read a seccomp profile JSON from disk.

    Args:
        name: Profile name (standard, hardened, permissive)

    Returns:
        Parsed JSON dict.

    Raises:
        FileNotFoundError: If profile does not exist.
        ValueError: If name is not valid.
    """
    if name not in VALID_SECCOMP_PROFILES:
        raise ValueError(f"Invalid seccomp profile: {name}")
    profile_path = Path(SECCOMP_PROFILES_DIR) / f"{name}.json"
    with open(profile_path, "r") as f:
        return json.load(f)


def _get_current_policy_label(container) -> Optional[str]:
    """Read the runtime policy label from a container.

    Checks ``cagent.runtime_policy`` first, falls back to
    ``cagent.seccomp_profile`` for backward compatibility with
    containers created before the runtime-policy rename.

    Returns None for unlabelled containers (including all existing ones
    before this feature was added).
    """
    try:
        container.reload()
        labels = container.labels or {}
        return labels.get("cagent.runtime_policy") or labels.get("cagent.seccomp_profile")
    except Exception as e:
        logger.debug("Failed to get runtime policy for container: %s", e)
        return None


def recreate_container_with_policy(container, policy_name: str) -> tuple:
    """Recreate a cell container with a new runtime policy.

    Applies the complete security posture (seccomp, capabilities,
    read-only root, tmpfs, no-new-privileges) from RUNTIME_POLICIES.

    Non-security settings (image, env, labels, mounts, dns, resources,
    networks, log_config, restart_policy) are copied from the old
    container.

    Args:
        container: Docker container object
        policy_name: One of standard, hardened, permissive

    Returns:
        (success: bool, message: str)
    """
    name = container.name
    policy = RUNTIME_POLICIES[policy_name]

    if policy_name == "permissive":
        logger.warning(
            f"Applying PERMISSIVE runtime policy to {name}. "
            "This relaxes capabilities, disables read-only root, and uses a permissive "
            "seccomp profile. Use only for temporary debugging."
        )
    logger.info(f"Recreating container {name} with runtime policy: {policy_name}")

    try:
        # Load seccomp profile for this policy
        profile_json = _load_seccomp_profile(policy["seccomp"])
        inline_json = json.dumps(profile_json)

        # Build security_opt from policy
        security_opt = [f"seccomp={inline_json}"]
        if policy["no_new_privileges"]:
            security_opt.append("no-new-privileges:true")

        # Inspect old container to capture non-security config
        container.reload()
        attrs = container.attrs
        config = attrs.get("Config", {})
        host_config = attrs.get("HostConfig", {})
        network_settings = attrs.get("NetworkSettings", {})

        # Capture non-security configuration from old container
        image = config.get("Image")
        env = config.get("Env", [])
        old_labels = dict(config.get("Labels", {}))

        # Update labels with new policy (set both for backward compat)
        old_labels["cagent.runtime_policy"] = policy_name
        old_labels["cagent.seccomp_profile"] = policy_name

        # Use attrs.Mounts as the single source of truth for ALL mount types.
        # This avoids duplicates when HostConfig.Binds and attrs.Mounts overlap
        # for named volumes, which causes Docker to reject the create() call.
        mounts = []
        for mount in attrs.get("Mounts", []):
            mount_type = mount.get("Type", "volume")
            if mount_type == "volume":
                mounts.append(
                    docker.types.Mount(
                        target=mount["Destination"],
                        source=mount["Name"],
                        type="volume",
                        read_only=not mount.get("RW", True),
                    )
                )
            elif mount_type == "bind":
                mounts.append(
                    docker.types.Mount(
                        target=mount["Destination"],
                        source=mount["Source"],
                        type="bind",
                        read_only=not mount.get("RW", True),
                    )
                )

        # DNS
        dns = host_config.get("Dns", [])

        # Restart policy
        restart_policy = host_config.get("RestartPolicy", {})

        # Resource limits
        nano_cpus = host_config.get("NanoCpus")
        memory = host_config.get("Memory")
        mem_reservation = host_config.get("MemoryReservation")

        # Log config
        log_config = host_config.get("LogConfig", {})

        # Networks
        networks_config = network_settings.get("Networks", {})

        # Stop but don't remove — keep as rollback target
        if container.status == "running":
            container.stop(timeout=10)
        temp_name = f"{name}__old"
        container.rename(temp_name)

        # Build create kwargs — security settings come from policy, not old container
        create_kwargs = {
            "image": image,
            "name": name,
            "environment": env,
            "labels": old_labels,
            "dns": dns if dns else None,
            "cap_drop": policy["cap_drop"] if policy["cap_drop"] else None,
            "cap_add": policy["cap_add"] if policy["cap_add"] else None,
            "read_only": policy["read_only"],
            "security_opt": security_opt,
            "network_disabled": True,
            "detach": True,
        }

        # tmpfs from policy
        if policy["tmpfs"]:
            # Docker SDK expects dict: {"/tmp": "size=100M", ...}
            create_kwargs["tmpfs"] = policy["tmpfs"]

        if mounts:
            create_kwargs["mounts"] = mounts
        if restart_policy:
            create_kwargs["restart_policy"] = restart_policy
        if nano_cpus:
            create_kwargs["nano_cpus"] = nano_cpus
        if memory:
            create_kwargs["mem_limit"] = memory
        if mem_reservation:
            create_kwargs["mem_reservation"] = mem_reservation
        if log_config and log_config.get("Type"):
            create_kwargs["log_config"] = docker.types.LogConfig(
                type=log_config["Type"],
                config=log_config.get("Config", {}),
            )

        # Create new container
        try:
            new_container = docker_client.containers.create(**create_kwargs)

            # Connect to original networks
            for net_name, net_config in networks_config.items():
                try:
                    network = docker_client.networks.get(net_name)
                    ip_addr = net_config.get("IPAddress")
                    connect_kwargs = {}
                    if ip_addr:
                        connect_kwargs["ipv4_address"] = ip_addr
                    network.connect(new_container, **connect_kwargs)
                except Exception as e:
                    logger.warning(f"Could not connect to network {net_name}: {e}")

            new_container.start()
        except Exception:
            # Rollback: restore old container
            container.rename(name)
            container.start()
            raise

        # Success — remove old container
        container.remove(force=True)

        msg = f"Container {name} recreated with runtime policy: {policy_name}"
        logger.info(msg)
        return True, msg

    except Exception as e:
        logger.error(f"Failed to recreate container {name} with runtime policy {policy_name}: {e}")
        return False, str(e)


def _get_current_resource_limits(container) -> dict:
    """Read current PIDs limit from a running container.

    Returns dict with pids_limit (int).
    Value is None if not set / unlimited.
    CPU and memory limits are hardcoded in docker-compose.yml and not propagated.
    """
    try:
        container.reload()
        host_config = container.attrs.get("HostConfig", {})

        # PIDs
        pids_limit = host_config.get("PidsLimit", 0)
        # Docker returns 0 or -1 for unlimited
        if pids_limit is not None and pids_limit <= 0:
            pids_limit = None

        return {
            "pids_limit": pids_limit,
        }
    except Exception as e:
        logger.warning(f"Could not read resource limits for {container.name}: {e}")
        return {"pids_limit": None}


def update_container_resources(container, pids_limit=None) -> tuple:
    """Update PIDs limit on a running container without recreation.

    Uses Docker's low-level /containers/{id}/update API directly because
    the Python SDK's container.update() is missing support for PidsLimit.

    CPU and memory limits are hardcoded in docker-compose.yml and not propagated.

    Args:
        container: Docker container object
        pids_limit: Max PIDs. None = no change.

    Returns:
        (success: bool, message: str)
    """
    name = container.name
    data = {}

    if pids_limit is not None:
        data["PidsLimit"] = pids_limit

    if not data:
        return True, "No resource changes needed"

    return _docker_container_update(container, data)


def _docker_container_update(container, data: dict) -> tuple:
    """Call Docker's /containers/{id}/update API directly.

    The Python SDK's container.update() is missing support for NanoCPUs
    and PidsLimit, so we use the low-level API.

    Returns (success: bool, message: str).
    """
    name = container.name
    try:
        logger.info(f"Updating resource limits on {name}: {data}")
        url = container.client.api._url("/containers/{0}/update", container.id)
        res = container.client.api._post_json(url, data=data)
        container.client.api._result(res, True)
        msg = f"Resource limits updated on {name}"
        logger.info(msg)
        return True, msg
    except Exception as e:
        logger.error(f"Failed to update resource limits on {name}: {e}")
        return False, str(e)


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------

_INFRA_CONTAINERS = [COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME, MITM_PROXY_CONTAINER_NAME]


def _infra_containers_ready() -> bool:
    """Return True if all infrastructure containers are running."""
    for name in _INFRA_CONTAINERS:
        try:
            c = docker_client.containers.get(name)
            if c.status != "running":
                return False
        except Exception as e:
            logger.debug("Infra container %r not ready: %s", name, e)
            return False
    return True


def get_container_status(container) -> dict:
    """Get status metrics for a single cell container."""
    try:
        container.reload()
    except docker.errors.APIError as e:
        logger.error(f"Docker API error reloading {container.name}: {e}")
        return {
            "status": "error",
            "container_id": None,
            "uptime_seconds": None,
            "cpu_percent": None,
            "memory_mb": None,
            "memory_limit_mb": None,
        }

    # Calculate uptime
    uptime_seconds = None
    if container.status == "running":
        started_at = container.attrs["State"]["StartedAt"]
        try:
            start_time = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            uptime_seconds = int((datetime.now(start_time.tzinfo) - start_time).total_seconds())
        except Exception as e:
            logger.debug("Failed to parse container uptime from %r: %s", started_at, e)

    # Get resource stats
    cpu_percent = None
    memory_mb = None
    memory_limit_mb = None

    if container.status == "running":
        try:
            stats = container.stats(stream=False)
            cpu_percent, memory_mb, memory_limit_mb = calculate_container_stats(stats)
        except Exception as e:
            logger.warning(f"Could not get container stats for {container.name}: {e}")

    return {
        "status": container.status,
        "container_id": container.short_id,
        "uptime_seconds": uptime_seconds,
        "cpu_percent": cpu_percent,
        "memory_mb": memory_mb,
        "memory_limit_mb": memory_limit_mb,
    }


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------


def execute_command(command: str, container, args: Optional[dict] = None) -> tuple:
    """Execute a command on a specific cell container.

    Returns (success: bool, message: str).
    """
    name = container.name
    logger.info(f"Executing command: {command} on {name} with args: {args}")

    try:
        if command == "restart":
            container.restart(timeout=10)
            return True, f"Cell container {name} restarted"

        elif command == "stop":
            container.stop(timeout=10)
            return True, f"Cell container {name} stopped"

        elif command == "start":
            container.start()
            return True, f"Cell container {name} started"

        elif command == "wipe":
            wipe_workspace = args.get("wipe_workspace", False) if args else False

            from routers.commands import _wipe_workspace

            if container.status == "running":
                container.stop(timeout=10)

            if wipe_workspace:
                _wipe_workspace(container)

            container.start()
            return True, f"Cell {name} wiped (workspace={'wiped' if wipe_workspace else 'preserved'})"

        elif command == "update_config":
            import runtime_config
            config = args.get("config", {}) if args else {}
            applied, rejected = runtime_config.validate_and_merge(config)
            # Handle SSH_AUTHORIZED_KEYS specially
            if "SSH_AUTHORIZED_KEYS" in applied:
                from routers.commands import _apply_ssh_keys
                _apply_ssh_keys(applied["SSH_AUTHORIZED_KEYS"])
            msg = f"Applied {len(applied)} key(s)"
            if rejected:
                msg += f", rejected {len(rejected)}: {'; '.join(rejected)}"
            return True, msg

        else:
            return False, f"Unknown command: {command}"

    except docker.errors.APIError as e:
        logger.error(f"Docker API error executing {command} on {name}: {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Error executing {command} on {name}: {e}")
        return False, str(e)
