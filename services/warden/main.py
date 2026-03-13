"""
Warden - Unified data plane service.

Combines the polling daemon (heartbeat, config sync, container management)
with the local admin HTTP API (config CRUD, container control, WebSocket
terminal, log streaming, analytics, domain policy, ext_authz credential
injection).

Runs as a FastAPI server with the polling loop in a background thread.
"""

import logging
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import requests
from alert_loop import alert_loop
from constants import (
    ALLOWED_CORS_ORIGINS,
    CONTROL_PLANE_URL,
    HEARTBEAT_URL,
    MTLS_CA_CERT_PATH,
    MTLS_CERT_PATH,
    MTLS_ENABLED,
    MTLS_KEY_PATH,
    MTLS_PORT,
    docker_client,
)
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from heartbeat_loop import main_loop

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - [trace=%(otelTraceID)s span=%(otelSpanID)s] - %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the polling loop in a resilient background thread.

    The loop auto-restarts on any crash (including BaseException such as
    KeyboardInterrupt delivered by uvicorn's signal handler to a non-main
    thread that happens to hold the GIL).
    """
    stop_event = threading.Event()

    def _loop_with_restart():
        while not stop_event.is_set():
            try:
                main_loop(stop_event)
            except Exception:
                logger.exception("Polling loop crashed, restarting in 5s")
            except BaseException as exc:
                # KeyboardInterrupt, SystemExit, etc. — log and restart
                logger.error("Polling loop killed by %s: %s — restarting in 5s", type(exc).__name__, exc)
            if not stop_event.is_set():
                time.sleep(5)

    def _alert_loop_with_restart():
        while not stop_event.is_set():
            try:
                alert_loop(stop_event)
            except Exception:
                logger.exception("Alert loop crashed, restarting in 5s")
            except BaseException as exc:
                logger.error("Alert loop killed by %s: %s — restarting in 5s", type(exc).__name__, exc)
            if not stop_event.is_set():
                time.sleep(5)

    loop_thread = threading.Thread(target=_loop_with_restart, daemon=True, name="polling-loop")
    loop_thread.start()
    logger.info("Polling loop thread started")

    alert_thread = threading.Thread(target=_alert_loop_with_restart, daemon=True, name="alert-loop")
    alert_thread.start()
    logger.info("Alert loop thread started")

    yield
    stop_event.set()


app = FastAPI(
    title="Cagent Warden",
    description="Unified data plane service: config management, container control, and CP sync",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OpenTelemetry tracing (opt-in via OTEL_ENABLED env var)
from tracing import setup_tracing

setup_tracing(app)

# Register routers
from routers import (
    analytics,
    commands,
    config,
    containers,
    domain_policy,
    ext_authz,
    health,
    logs,
    policies,
    status,
    terminal,
)
from warden_auth import verify_warden_token

# Health and ext_authz are public (no warden token required)
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(ext_authz.router, tags=["ext-authz"])

# All other routers require warden token auth (when WARDEN_API_TOKEN is set)
_auth_deps = [Depends(verify_warden_token)]
app.include_router(config.router, prefix="/api", tags=["config"], dependencies=_auth_deps)
app.include_router(containers.router, prefix="/api", tags=["containers"], dependencies=_auth_deps)
app.include_router(logs.router, prefix="/api", tags=["logs"], dependencies=_auth_deps)
app.include_router(terminal.router, prefix="/api", tags=["terminal"], dependencies=_auth_deps)
app.include_router(analytics.router, prefix="/api", tags=["analytics"], dependencies=_auth_deps)
app.include_router(domain_policy.router, tags=["domain-policy"], dependencies=_auth_deps)
app.include_router(commands.router, prefix="/api", tags=["commands"], dependencies=_auth_deps)
app.include_router(status.router, prefix="/api", tags=["status"], dependencies=_auth_deps)
app.include_router(policies.router, prefix="/api", tags=["policies"], dependencies=_auth_deps)

# =============================================================================
# Static files (frontend)
# =============================================================================

FRONTEND_DIR = Path(__file__).parent / "frontend" / "dist"
if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        """Serve frontend for all non-API routes."""
        if path.startswith("api/"):
            raise HTTPException(404)

        try:
            # Resolve the requested path relative to FRONTEND_DIR
            file_path = (FRONTEND_DIR / path).resolve()

            # Ensure the resolved path is still within FRONTEND_DIR
            # This prevents path traversal attacks (e.g., /../../etc/passwd)
            if not file_path.is_relative_to(FRONTEND_DIR.resolve()):
                # Path traversal detected - return index.html (SPA fallback)
                return FileResponse(FRONTEND_DIR / "index.html")

            if file_path.exists() and file_path.is_file():
                return FileResponse(file_path)
        except Exception as e:
            logger.debug("SPA path resolution error for %r: %s", path, e)

        return FileResponse(FRONTEND_DIR / "index.html")


if __name__ == "__main__":
    import asyncio
    import ssl

    import uvicorn

    try:
        # Verify Docker connection
        docker_client.ping()
        logger.info("Docker connection verified")
    except Exception as e:
        logger.error(f"Cannot connect to Docker: {e}")
        sys.exit(1)

    if MTLS_ENABLED:
        logger.info("mTLS enabled — starting HTTP (8080) + HTTPS+mTLS (%d)", MTLS_PORT)

        http_config = uvicorn.Config(app, host="0.0.0.0", port=8080, lifespan="off")
        https_config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=MTLS_PORT,
            ssl_certfile=MTLS_CERT_PATH,
            ssl_keyfile=MTLS_KEY_PATH,
            ssl_ca_certs=MTLS_CA_CERT_PATH,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            lifespan="off",
        )

        http_server = uvicorn.Server(http_config)
        https_server = uvicorn.Server(https_config)

        async def _serve_both():
            async with lifespan(app):
                await asyncio.gather(http_server.serve(), https_server.serve())

        asyncio.run(_serve_both())
    else:
        logger.info("mTLS not configured — HTTP-only on 8080")
        uvicorn.run(app, host="0.0.0.0", port=8080)
