import logging
from datetime import datetime
from typing import Optional

import docker
from constants import ALLOWED_CORS_ORIGINS, docker_client, get_managed_containers
from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from utils import async_generator, validate_websocket_origin

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/containers/{name}/logs")
def get_container_logs(name: str, tail: int = 100, since: Optional[str] = None):
    """Get container logs."""
    # Restrict access to managed containers only
    if name not in get_managed_containers():
        raise HTTPException(403, f"Access denied: {name} is not a managed container")

    try:
        container = docker_client.containers.get(name)

        kwargs = {"tail": tail, "timestamps": True}
        if since:
            kwargs["since"] = since

        logs = container.logs(**kwargs).decode("utf-8")
        lines = logs.strip().split("\n") if logs.strip() else []

        return {"container": name, "lines": lines, "count": len(lines)}

    except docker.errors.NotFound:
        raise HTTPException(404, f"Container not found: {name}")
    except Exception as e:
        raise HTTPException(500, str(e))


@router.websocket("/containers/{name}/logs/stream")
async def stream_container_logs(websocket: WebSocket, name: str):
    """Stream container logs via WebSocket."""
    if not validate_websocket_origin(websocket, ALLOWED_CORS_ORIGINS):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Restrict access to managed containers only
    if name not in get_managed_containers():
        await websocket.send_text(f"ERROR: Access denied: {name} is not a managed container")
        await websocket.close()
        return

    try:
        container = docker_client.containers.get(name)

        # Stream logs (run blocking generator in thread to avoid blocking event loop)
        async for log in async_generator(container.logs(stream=True, follow=True, timestamps=True, tail=50)):
            try:
                await websocket.send_text(log.decode("utf-8"))
            except WebSocketDisconnect:
                break

    except docker.errors.NotFound:
        await websocket.send_text(f"ERROR: Container not found: {name}")
    except Exception as e:
        await websocket.send_text(f"ERROR: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@router.get("/logs/search")
async def search_logs(
    query: str = "",
    source: Optional[str] = None,
    cell_id: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    """Search logs from local VictoriaLogs.

    Falls back to empty results if VL is unavailable.
    """
    try:
        from victorialogs_client import datetime_to_us, now_us, query_logs

        # Build time range
        end_us = now_us()
        start_us = end_us - 6 * 3600 * 1_000_000  # default 6h

        if end:
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
            end_us = datetime_to_us(end_dt)
        if start:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            start_us = datetime_to_us(start_dt)

        # Build LogsQL query — quote all user input to prevent injection.
        # LogsQL special chars: | * ( ) " \
        def _escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')

        filters = []
        if query:
            filters.append(f'_msg:"{_escape(query)}"')
        if source:
            filters.append(f'source:"{_escape(source)}"')
        if cell_id:
            filters.append(f'cell_id:"{_escape(cell_id)}"')

        logsql = " AND ".join(filters) if filters else "*"
        logsql += f" | sort by (_time) desc | limit {limit}"

        hits = query_logs(logsql, start_us, end_us)
        # Map VictoriaLogs field names to frontend-expected names
        for hit in hits:
            if "_msg" in hit and "message" not in hit:
                hit["message"] = hit["_msg"]
            if "_time" in hit and "timestamp" not in hit:
                hit["timestamp"] = hit["_time"]
        return {"hits": hits, "total": len(hits)}

    except ImportError:
        logger.debug("VictoriaLogs client not available, returning empty results")
        return {"hits": [], "total": 0}
