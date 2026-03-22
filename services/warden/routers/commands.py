"""Command execution endpoints for connected mode.

The CP pushes commands via mTLS instead of queuing them
in the DB for the next heartbeat poll.
"""

import io
import logging
import tarfile
from pathlib import Path
from typing import Optional

import docker
import runtime_config
from constants import docker_client
from fastapi import APIRouter, HTTPException
from constants import discover_cell_containers
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_cell_container():
    """Get the first discovered cell container."""
    containers = discover_cell_containers()
    if not containers:
        raise HTTPException(status_code=404, detail="No cell container found")
    return containers[0]


def _get_workspace_mount(container) -> Optional[dict]:
    """Return the /workspace mount info from container attrs, or None."""
    container.reload()
    for mount in container.attrs.get("Mounts", []):
        if mount.get("Destination") == "/workspace":
            return mount
    return None


def _wipe_workspace(container) -> None:
    """Clear the /workspace contents.  Container must be stopped.

    Handles both mount types:
    - Named volume: mount in throwaway container and delete contents
    - Bind mount: mount in throwaway container and delete contents
    """
    mount = _get_workspace_mount(container)
    if not mount:
        logger.warning("No /workspace mount found on %s — skipping workspace wipe", container.name)
        return

    mount_type = mount.get("Type", "volume")
    image = container.attrs.get("Config", {}).get("Image")

    if mount_type == "volume":
        vol_name = mount["Name"]
        logger.info("Wiping workspace: clearing volume %s using image %s", vol_name, image)
        docker_client.containers.run(
            image,
            entrypoint="/bin/sh",
            command=["-c", "find /workspace -mindepth 1 -delete"],
            mounts=[docker.types.Mount(target="/workspace", source=vol_name, type="volume")],
            remove=True,
            network_disabled=True,
        )

    elif mount_type == "bind":
        source = mount["Source"]
        logger.info("Wiping workspace: clearing bind mount %s using image %s", source, image)
        docker_client.containers.run(
            image,
            entrypoint="/bin/sh",
            command=["-c", "find /workspace -mindepth 1 -delete"],
            volumes={source: {"bind": "/workspace", "mode": "rw"}},
            remove=True,
            network_disabled=True,
        )

    else:
        logger.warning("Unknown mount type %s for /workspace on %s — skipping", mount_type, container.name)
        return

    logger.info("Workspace wiped for %s", container.name)


class WipeRequest(BaseModel):
    wipe_workspace: bool = False


@router.post("/commands/wipe")
def wipe_cell(body: Optional[WipeRequest] = None):
    """Wipe the cell: stop, optionally clear workspace, restart.

    The same container is reused — no rename or recreation needed.
    """
    wipe_workspace = body.wipe_workspace if body else False
    container = _get_cell_container()
    name = container.name
    try:
        container.stop(timeout=10)

        if wipe_workspace:
            _wipe_workspace(container)

        container.start()
        return {
            "status": "completed",
            "command": "wipe",
            "message": f"Container {name} wiped (workspace={'wiped' if wipe_workspace else 'preserved'})",
        }
    except HTTPException:
        raise
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Wipe failed: {e}")


@router.post("/commands/restart")
def restart_cell():
    """Restart the cell container."""
    container = _get_cell_container()
    try:
        container.restart(timeout=10)
        return {"status": "completed", "command": "restart", "message": f"Container {container.name} restarted"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Restart failed: {e}")


@router.post("/commands/stop")
def stop_cell():
    """Stop the cell container."""
    container = _get_cell_container()
    try:
        container.stop(timeout=10)
        return {"status": "completed", "command": "stop", "message": f"Container {container.name} stopped"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Stop failed: {e}")


@router.post("/commands/start")
def start_cell():
    """Start the cell container."""
    container = _get_cell_container()
    try:
        container.start()
        return {"status": "completed", "command": "start", "message": f"Container {container.name} started"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Start failed: {e}")


class UpdateConfigRequest(BaseModel):
    config: dict


@router.post("/commands/update-config")
def update_config(body: UpdateConfigRequest):
    """Apply runtime config overrides pushed from the control plane."""
    applied, rejected = runtime_config.validate_and_merge(body.config)

    # Handle SSH_AUTHORIZED_KEYS specially: write to cell container
    if "SSH_AUTHORIZED_KEYS" in applied:
        _apply_ssh_keys(applied["SSH_AUTHORIZED_KEYS"])

    # Handle mTLS cert updates: overwrite PEM files and restart warden
    mtls_keys = {"WARDEN_TLS_CERT", "WARDEN_TLS_KEY", "WARDEN_MTLS_CA_CERT"}
    needs_restart = bool(mtls_keys & applied.keys())
    if needs_restart:
        _apply_mtls_certs(applied)

    return {
        "status": "completed",
        "command": "update_config",
        "message": f"Applied {len(applied)} key(s)" + (f", rejected {len(rejected)}" if rejected else "")
        + ("; warden restart scheduled for cert update" if needs_restart else ""),
        "applied": {k: v for k, v in applied.items() if k not in mtls_keys},
        "rejected": rejected,
        "restart_scheduled": needs_restart,
    }


def _apply_ssh_keys(keys: str):
    """Write SSH authorized_keys into all cell containers.

    Uses docker exec instead of put_archive because cell containers
    have a read-only rootfs with /home/cell as a tmpfs mount.
    """
    containers = discover_cell_containers()
    for container in containers:
        try:
            # Use base64 to safely transport the key content without shell escaping issues
            import base64
            encoded = base64.b64encode(keys.encode()).decode()
            exit_code, output = container.exec_run(
                ["sh", "-c",
                 f"echo '{encoded}' | base64 -d > /home/cell/.ssh/authorized_keys"
                 " && chmod 600 /home/cell/.ssh/authorized_keys"
                 " && chown cell:cell /home/cell/.ssh/authorized_keys"],
                user="root",
            )
            if exit_code == 0:
                logger.info("SSH authorized_keys updated in %s", container.name)
            else:
                logger.error("Failed to update SSH keys in %s (exit %d): %s", container.name, exit_code, output)
        except Exception as e:
            logger.error("Failed to update SSH authorized_keys in %s: %s", container.name, e)


def _apply_mtls_certs(applied: dict):
    """Overwrite mTLS PEM files and schedule warden container restart.

    New certs are base64-encoded in the applied dict. We decode and overwrite
    the existing temp PEM files, then restart the warden container so uvicorn
    picks up the new SSL context.
    """
    import base64
    import threading
    from constants import MTLS_CERT_PATH, MTLS_KEY_PATH, MTLS_CA_CERT_PATH, WARDEN_CONTAINER_NAME

    cert_map = {
        "WARDEN_TLS_CERT": MTLS_CERT_PATH,
        "WARDEN_TLS_KEY": MTLS_KEY_PATH,
        "WARDEN_MTLS_CA_CERT": MTLS_CA_CERT_PATH,
    }

    for key, path in cert_map.items():
        if key in applied and path:
            try:
                raw = base64.b64decode(applied[key])
                Path(path).write_bytes(raw)
                logger.info("Updated mTLS cert file: %s", path)
            except Exception as e:
                logger.error("Failed to write %s to %s: %s", key, path, e)

    # Schedule a delayed self-restart so we can return the response first
    def _restart_warden():
        import time
        time.sleep(2)
        try:
            container = docker_client.containers.get(WARDEN_CONTAINER_NAME)
            container.restart(timeout=10)
            logger.info("Warden container restarted for mTLS cert update")
        except Exception as e:
            logger.error("Failed to restart warden: %s", e)

    threading.Thread(target=_restart_warden, daemon=True).start()


@router.get("/commands/runtime-config")
def get_runtime_config():
    """Return current effective runtime config (overrides + defaults)."""
    from constants import HEARTBEAT_INTERVAL, CONFIG_SYNC_INTERVAL, ALERT_CHECK_INTERVAL
    from constants import OPENOBSERVE_URL, OPENOBSERVE_USER, BETA_FEATURES
    from constants import WARDEN_API_TOKEN, MTLS_ENABLED

    overrides = runtime_config.load()
    effective = {
        "HEARTBEAT_INTERVAL": int(runtime_config.get("HEARTBEAT_INTERVAL", HEARTBEAT_INTERVAL)),
        "CONFIG_SYNC_INTERVAL": int(runtime_config.get("CONFIG_SYNC_INTERVAL", CONFIG_SYNC_INTERVAL)),
        "ALERT_CHECK_INTERVAL": int(runtime_config.get("ALERT_CHECK_INTERVAL", ALERT_CHECK_INTERVAL)),
        "OPENOBSERVE_URL": runtime_config.get("OPENOBSERVE_URL", OPENOBSERVE_URL),
        "OPENOBSERVE_USER": runtime_config.get("OPENOBSERVE_USER", OPENOBSERVE_USER),
        "BETA_FEATURES": runtime_config.get("BETA_FEATURES", ",".join(BETA_FEATURES)),
        "WARDEN_API_TOKEN": "(set)" if runtime_config.get("WARDEN_API_TOKEN", WARDEN_API_TOKEN) else "(not set)",
        "MTLS_ENABLED": MTLS_ENABLED,
        "WARDEN_TLS_CERT": "(overridden)" if "WARDEN_TLS_CERT" in overrides else "(default)",
        "WARDEN_TLS_KEY": "(overridden)" if "WARDEN_TLS_KEY" in overrides else "(default)",
        "WARDEN_MTLS_CA_CERT": "(overridden)" if "WARDEN_MTLS_CA_CERT" in overrides else "(default)",
    }
    return {
        "overrides": overrides,
        "effective": effective,
        "updatable_keys": list(runtime_config.UPDATABLE_KEYS.keys()),
    }
