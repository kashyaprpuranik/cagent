"""Command execution endpoints for connected mode.

The CP pushes commands via mTLS instead of queuing them
in the DB for the next heartbeat poll.
"""

import io
import logging
import tarfile
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
        container.restart(timeout=30)
        return {"status": "completed", "command": "restart", "message": f"Container {container.name} restarted"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Restart failed: {e}")


@router.post("/commands/stop")
def stop_cell():
    """Stop the cell container."""
    container = _get_cell_container()
    try:
        container.stop(timeout=30)
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

    return {
        "status": "completed",
        "command": "update_config",
        "message": f"Applied {len(applied)} key(s)" + (f", rejected {len(rejected)}" if rejected else ""),
        "applied": applied,
        "rejected": rejected,
    }


def _apply_ssh_keys(keys: str):
    """Write SSH authorized_keys into the cell container."""
    try:
        container = _get_cell_container()
        keys_content = keys.encode("utf-8")
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name="authorized_keys")
            info.size = len(keys_content)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(keys_content))
        tar_stream.seek(0)
        container.put_archive("/home/cell/.ssh", tar_stream)
        logger.info("SSH authorized_keys updated in cell container")
    except Exception as e:
        logger.error("Failed to update SSH authorized_keys: %s", e)


@router.get("/commands/runtime-config")
def get_runtime_config():
    """Return current effective runtime config (overrides + defaults)."""
    from constants import HEARTBEAT_INTERVAL, CONFIG_SYNC_INTERVAL, ALERT_CHECK_INTERVAL
    from constants import OPENOBSERVE_URL, OPENOBSERVE_USER, BETA_FEATURES

    overrides = runtime_config.load()
    effective = {
        "HEARTBEAT_INTERVAL": int(runtime_config.get("HEARTBEAT_INTERVAL", HEARTBEAT_INTERVAL)),
        "CONFIG_SYNC_INTERVAL": int(runtime_config.get("CONFIG_SYNC_INTERVAL", CONFIG_SYNC_INTERVAL)),
        "ALERT_CHECK_INTERVAL": int(runtime_config.get("ALERT_CHECK_INTERVAL", ALERT_CHECK_INTERVAL)),
        "OPENOBSERVE_URL": runtime_config.get("OPENOBSERVE_URL", OPENOBSERVE_URL),
        "OPENOBSERVE_USER": runtime_config.get("OPENOBSERVE_USER", OPENOBSERVE_USER),
        "BETA_FEATURES": runtime_config.get("BETA_FEATURES", ",".join(BETA_FEATURES)),
    }
    return {
        "overrides": overrides,
        "effective": effective,
        "updatable_keys": list(runtime_config.UPDATABLE_KEYS.keys()),
    }
