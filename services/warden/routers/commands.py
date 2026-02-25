"""Command execution endpoints for interactive mode.

The CP pushes commands via Cloudflare Tunnel instead of queuing them
in the DB for the next heartbeat poll.
"""

import logging

import docker
from constants import docker_client
from fastapi import APIRouter, HTTPException
from main import discover_cell_containers

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_cell_container():
    """Get the first discovered cell container."""
    containers = discover_cell_containers()
    if not containers:
        raise HTTPException(status_code=404, detail="No cell container found")
    return containers[0]


@router.post("/commands/restart")
async def restart_cell():
    """Restart the cell container."""
    container = _get_cell_container()
    try:
        container.restart(timeout=30)
        return {"status": "completed", "command": "restart", "message": f"Container {container.name} restarted"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Restart failed: {e}")


@router.post("/commands/stop")
async def stop_cell():
    """Stop the cell container."""
    container = _get_cell_container()
    try:
        container.stop(timeout=30)
        return {"status": "completed", "command": "stop", "message": f"Container {container.name} stopped"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Stop failed: {e}")


@router.post("/commands/start")
async def start_cell():
    """Start the cell container."""
    container = _get_cell_container()
    try:
        container.start()
        return {"status": "completed", "command": "start", "message": f"Container {container.name} started"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Start failed: {e}")


@router.post("/commands/wipe")
async def wipe_cell():
    """Stop, remove, and recreate the cell container."""
    container = _get_cell_container()
    name = container.name
    try:
        # Capture config before removal
        attrs = container.attrs
        image = attrs["Config"]["Image"]

        container.stop(timeout=10)
        container.remove(force=True)

        # Recreate with same image (simplified — full recreation uses compose)
        new_container = docker_client.containers.run(
            image,
            name=name,
            detach=True,
            labels={"cagent.role": "cell", "cagent.log-collect": "true"},
        )
        return {
            "status": "completed",
            "command": "wipe",
            "message": f"Container {name} wiped and recreated as {new_container.short_id}",
        }
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Wipe failed: {e}")
