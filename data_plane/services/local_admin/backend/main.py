"""
Local Admin API - Lightweight management API for standalone data plane.

Provides:
- Config management (read/write cagent.yaml)
- Container status and control
- Log streaming
- No authentication (localhost only)
"""

import os
import yaml
import asyncio
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

import docker

# Configuration
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
AGENT_CONTAINER_NAME = os.environ.get("AGENT_CONTAINER_NAME", "agent")
COREDNS_CONTAINER_NAME = os.environ.get("COREDNS_CONTAINER_NAME", "dns-filter")
ENVOY_CONTAINER_NAME = os.environ.get("ENVOY_CONTAINER_NAME", "envoy-proxy")
FRPC_CONTAINER_NAME = os.environ.get("FRPC_CONTAINER_NAME", "frpc")
DATA_PLANE_DIR = os.environ.get("DATA_PLANE_DIR", "/app/data_plane")

app = FastAPI(
    title="Cagent Local Admin",
    description="Local management API for standalone data plane",
    version="1.0.0"
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Docker client
docker_client = docker.from_env()


# =============================================================================
# Models
# =============================================================================

class DomainEntry(BaseModel):
    domain: str
    alias: Optional[str] = None
    timeout: Optional[str] = None
    read_only: Optional[bool] = None
    rate_limit: Optional[dict] = None
    credential: Optional[dict] = None


class ConfigUpdate(BaseModel):
    domains: Optional[list[DomainEntry]] = None
    dns: Optional[dict] = None
    rate_limits: Optional[dict] = None
    mode: Optional[str] = None


class ContainerAction(BaseModel):
    action: str  # start, stop, restart


class SshTunnelConfig(BaseModel):
    frp_server_addr: str
    frp_server_port: int = 7000
    frp_auth_token: str
    agent_id: str
    stcp_secret_key: Optional[str] = None  # Auto-generated if not provided


class SshTunnelStatus(BaseModel):
    enabled: bool
    connected: bool
    agent_id: Optional[str] = None
    frp_server: Optional[str] = None
    container_status: Optional[str] = None
    stcp_secret_key: Optional[str] = None


# =============================================================================
# Health
# =============================================================================

@app.get("/api/health")
async def health():
    """Health check."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/health/detailed")
async def detailed_health():
    """Detailed health check for all components."""
    checks = {}

    # Check each container
    for name in [AGENT_CONTAINER_NAME, COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME]:
        try:
            container = docker_client.containers.get(name)
            container.reload()
            checks[name] = {
                "status": "healthy" if container.status == "running" else "unhealthy",
                "container_status": container.status,
                "uptime": container.attrs["State"].get("StartedAt") if container.status == "running" else None,
            }
        except docker.errors.NotFound:
            checks[name] = {"status": "missing", "container_status": "not_found"}
        except Exception as e:
            checks[name] = {"status": "error", "error": str(e)}

    # Test DNS resolution (via CoreDNS container)
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        if container.status == "running":
            # Try to resolve a test domain
            result = container.exec_run(["nslookup", "google.com", "127.0.0.1"], timeout=5)
            checks["dns_resolution"] = {
                "status": "healthy" if result.exit_code == 0 else "unhealthy",
                "test": "google.com",
            }
        else:
            checks["dns_resolution"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["dns_resolution"] = {"status": "error", "error": str(e)}

    # Test Envoy health endpoint
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
        if container.status == "running":
            result = container.exec_run(["wget", "-q", "-O", "-", "http://localhost:9901/ready"], timeout=5)
            checks["envoy_ready"] = {
                "status": "healthy" if result.exit_code == 0 else "unhealthy",
            }
        else:
            checks["envoy_ready"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["envoy_ready"] = {"status": "error", "error": str(e)}

    # Overall status
    all_healthy = all(c.get("status") == "healthy" for c in checks.values())

    return {
        "status": "healthy" if all_healthy else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    }


@app.get("/api/info")
async def info():
    """System info."""
    return {
        "mode": "standalone",
        "config_path": CAGENT_CONFIG_PATH,
        "data_plane_dir": DATA_PLANE_DIR,
        "containers": {
            "agent": AGENT_CONTAINER_NAME,
            "dns": COREDNS_CONTAINER_NAME,
            "envoy": ENVOY_CONTAINER_NAME,
            "frpc": FRPC_CONTAINER_NAME
        }
    }


# =============================================================================
# Configuration
# =============================================================================

@app.get("/api/config")
async def get_config():
    """Get current cagent.yaml configuration."""
    config_path = Path(CAGENT_CONFIG_PATH)
    if not config_path.exists():
        raise HTTPException(404, f"Config file not found: {CAGENT_CONFIG_PATH}")

    content = config_path.read_text()
    config = yaml.safe_load(content)

    return {
        "config": config,
        "raw": content,
        "path": str(config_path),
        "modified": datetime.fromtimestamp(config_path.stat().st_mtime).isoformat()
    }


@app.put("/api/config")
async def update_config(update: ConfigUpdate):
    """Update cagent.yaml configuration."""
    config_path = Path(CAGENT_CONFIG_PATH)

    # Read current config
    if config_path.exists():
        current = yaml.safe_load(config_path.read_text())
    else:
        current = {}

    # Apply updates
    if update.domains is not None:
        current["domains"] = [d.model_dump(exclude_none=True) for d in update.domains]
    if update.dns is not None:
        current["dns"] = update.dns
    if update.rate_limits is not None:
        current["rate_limits"] = update.rate_limits
    if update.mode is not None:
        current["mode"] = update.mode

    # Write back
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(current, default_flow_style=False, sort_keys=False))

    return {"status": "updated", "config": current}


@app.put("/api/config/raw")
async def update_config_raw(body: dict):
    """Update cagent.yaml with raw YAML content."""
    config_path = Path(CAGENT_CONFIG_PATH)
    content = body.get("content", "")

    # Validate YAML
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")

    # Write
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content)

    return {"status": "updated"}


@app.post("/api/config/reload")
async def reload_config():
    """Trigger config reload (regenerate CoreDNS + Envoy configs)."""
    # This would trigger agent-manager to reload
    # For now, we restart the containers
    results = {}

    for name in [COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME]:
        try:
            container = docker_client.containers.get(name)
            container.restart(timeout=10)
            results[name] = "restarted"
        except docker.errors.NotFound:
            results[name] = "not_found"
        except Exception as e:
            results[name] = f"error: {e}"

    return {"status": "reload_triggered", "results": results}


# =============================================================================
# Containers
# =============================================================================

def get_container_info(name: str) -> dict:
    """Get container status info."""
    try:
        container = docker_client.containers.get(name)
        container.reload()

        info = {
            "name": name,
            "status": container.status,
            "id": container.short_id,
            "image": container.image.tags[0] if container.image.tags else "unknown",
            "created": container.attrs["Created"],
        }

        if container.status == "running":
            info["started_at"] = container.attrs["State"]["StartedAt"]

            # Get stats
            try:
                stats = container.stats(stream=False)

                # CPU
                cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                           stats["precpu_stats"]["cpu_usage"]["total_usage"]
                system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                              stats["precpu_stats"]["system_cpu_usage"]
                num_cpus = stats["cpu_stats"].get("online_cpus", 1)

                if system_delta > 0:
                    info["cpu_percent"] = round((cpu_delta / system_delta) * num_cpus * 100, 2)

                # Memory
                memory_usage = stats["memory_stats"].get("usage", 0)
                memory_limit = stats["memory_stats"].get("limit", 0)
                info["memory_mb"] = round(memory_usage / (1024 * 1024), 2)
                info["memory_limit_mb"] = round(memory_limit / (1024 * 1024), 2)
            except Exception:
                pass

        return info

    except docker.errors.NotFound:
        return {"name": name, "status": "not_found"}
    except Exception as e:
        return {"name": name, "status": "error", "error": str(e)}


@app.get("/api/containers")
async def list_containers():
    """Get status of all managed containers."""
    containers = {}

    for name in [AGENT_CONTAINER_NAME, COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME]:
        containers[name] = get_container_info(name)

    return {"containers": containers}


@app.get("/api/containers/{name}")
async def get_container(name: str):
    """Get status of a specific container."""
    return get_container_info(name)


@app.post("/api/containers/{name}")
async def control_container(name: str, action: ContainerAction):
    """Control a container (start/stop/restart)."""
    try:
        container = docker_client.containers.get(name)

        if action.action == "start":
            container.start()
        elif action.action == "stop":
            container.stop(timeout=10)
        elif action.action == "restart":
            container.restart(timeout=10)
        else:
            raise HTTPException(400, f"Unknown action: {action.action}")

        return {"status": "ok", "action": action.action, "container": name}

    except docker.errors.NotFound:
        raise HTTPException(404, f"Container not found: {name}")
    except Exception as e:
        raise HTTPException(500, str(e))


# =============================================================================
# Logs
# =============================================================================

@app.get("/api/containers/{name}/logs")
async def get_container_logs(name: str, tail: int = 100, since: Optional[str] = None):
    """Get container logs."""
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


@app.websocket("/api/containers/{name}/logs/stream")
async def stream_container_logs(websocket: WebSocket, name: str):
    """Stream container logs via WebSocket."""
    await websocket.accept()

    try:
        container = docker_client.containers.get(name)

        # Stream logs
        for log in container.logs(stream=True, follow=True, timestamps=True, tail=50):
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


# =============================================================================
# Web Terminal
# =============================================================================

@app.websocket("/api/terminal/{name}")
async def web_terminal(websocket: WebSocket, name: str):
    """Interactive terminal session via WebSocket."""
    await websocket.accept()

    try:
        container = docker_client.containers.get(name)

        if container.status != "running":
            await websocket.send_text(f"\r\nContainer '{name}' is not running.\r\n")
            await websocket.close()
            return

        # Create exec instance with TTY
        exec_id = docker_client.api.exec_create(
            container.id,
            cmd="/bin/bash",
            stdin=True,
            tty=True,
            stdout=True,
            stderr=True,
        )

        # Start exec with socket
        sock = docker_client.api.exec_start(
            exec_id["Id"],
            socket=True,
            tty=True,
        )

        # Get the raw socket
        raw_sock = sock._sock

        async def read_from_container():
            """Read output from container and send to websocket."""
            loop = asyncio.get_event_loop()
            while True:
                try:
                    data = await loop.run_in_executor(None, lambda: raw_sock.recv(4096))
                    if not data:
                        break
                    await websocket.send_text(data.decode("utf-8", errors="replace"))
                except Exception:
                    break

        async def write_to_container():
            """Read from websocket and send to container."""
            while True:
                try:
                    data = await websocket.receive_text()
                    raw_sock.sendall(data.encode("utf-8"))
                except WebSocketDisconnect:
                    break
                except Exception:
                    break

        # Run both tasks concurrently
        await asyncio.gather(
            read_from_container(),
            write_to_container(),
            return_exceptions=True
        )

    except docker.errors.NotFound:
        await websocket.send_text(f"\r\nContainer '{name}' not found.\r\n")
    except Exception as e:
        await websocket.send_text(f"\r\nError: {e}\r\n")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# =============================================================================
# SSH Tunnel (FRP/STCP)
# =============================================================================

def read_env_file() -> dict:
    """Read current .env file if it exists."""
    env_path = Path(DATA_PLANE_DIR) / ".env"
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env_vars[key.strip()] = value.strip().strip('"').strip("'")
    return env_vars


def write_env_file(env_vars: dict):
    """Write .env file with updated variables."""
    env_path = Path(DATA_PLANE_DIR) / ".env"
    lines = []

    # Read existing file to preserve comments and order
    existing_keys = set()
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                lines.append(line)
            elif "=" in stripped:
                key = stripped.split("=", 1)[0].strip()
                existing_keys.add(key)
                if key in env_vars:
                    lines.append(f"{key}={env_vars[key]}")
                else:
                    lines.append(line)

    # Add new keys
    for key, value in env_vars.items():
        if key not in existing_keys:
            lines.append(f"{key}={value}")

    env_path.write_text("\n".join(lines) + "\n")


def get_frpc_status() -> dict:
    """Get FRP client container status."""
    try:
        container = docker_client.containers.get(FRPC_CONTAINER_NAME)
        container.reload()
        return {
            "exists": True,
            "status": container.status,
            "id": container.short_id
        }
    except docker.errors.NotFound:
        return {"exists": False, "status": "not_found"}
    except Exception as e:
        return {"exists": False, "status": "error", "error": str(e)}


@app.get("/api/ssh-tunnel")
async def get_ssh_tunnel_status():
    """Get SSH tunnel status and configuration."""
    env_vars = read_env_file()
    frpc_status = get_frpc_status()

    return {
        "enabled": frpc_status.get("exists", False) and frpc_status.get("status") == "running",
        "connected": frpc_status.get("status") == "running",
        "agent_id": env_vars.get("AGENT_ID"),
        "frp_server": env_vars.get("FRP_SERVER_ADDR"),
        "frp_server_port": env_vars.get("FRP_SERVER_PORT", "7000"),
        "container_status": frpc_status.get("status"),
        "stcp_secret_key": env_vars.get("STCP_SECRET_KEY"),
        "configured": bool(env_vars.get("FRP_SERVER_ADDR") and env_vars.get("STCP_SECRET_KEY"))
    }


@app.post("/api/ssh-tunnel/generate-key")
async def generate_stcp_key():
    """Generate a new STCP secret key."""
    key = secrets.token_urlsafe(32)
    return {"stcp_secret_key": key}


@app.post("/api/ssh-tunnel/configure")
async def configure_ssh_tunnel(config: SshTunnelConfig):
    """Configure SSH tunnel with FRP settings."""
    # Generate secret key if not provided
    stcp_key = config.stcp_secret_key or secrets.token_urlsafe(32)

    # Update .env file
    env_updates = {
        "FRP_SERVER_ADDR": config.frp_server_addr,
        "FRP_SERVER_PORT": str(config.frp_server_port),
        "FRP_AUTH_TOKEN": config.frp_auth_token,
        "AGENT_ID": config.agent_id,
        "STCP_SECRET_KEY": stcp_key
    }

    try:
        write_env_file(env_updates)
    except Exception as e:
        raise HTTPException(500, f"Failed to write .env file: {e}")

    return {
        "status": "configured",
        "agent_id": config.agent_id,
        "stcp_secret_key": stcp_key,
        "message": "Configuration saved. Use start endpoint to enable tunnel."
    }


def create_frpc_container(env_vars: dict):
    """Create the frpc container using Docker SDK."""
    # Get or create networks
    try:
        agent_net = docker_client.networks.get("data_plane_agent-net")
    except docker.errors.NotFound:
        raise HTTPException(500, "Network data_plane_agent-net not found. Is the data plane running?")

    try:
        infra_net = docker_client.networks.get("data_plane_infra-net")
    except docker.errors.NotFound:
        raise HTTPException(500, "Network data_plane_infra-net not found. Is the data plane running?")

    # Create container
    container = docker_client.containers.create(
        image="snowdreamtech/frpc:latest",
        name=FRPC_CONTAINER_NAME,
        environment={
            "FRP_SERVER_ADDR": env_vars.get("FRP_SERVER_ADDR"),
            "FRP_SERVER_PORT": env_vars.get("FRP_SERVER_PORT", "7000"),
            "FRP_AUTH_TOKEN": env_vars.get("FRP_AUTH_TOKEN"),
            "AGENT_ID": env_vars.get("AGENT_ID"),
            "STCP_SECRET_KEY": env_vars.get("STCP_SECRET_KEY"),
        },
        volumes={
            f"{DATA_PLANE_DIR}/configs/frpc/frpc.toml": {"bind": "/etc/frp/frpc.toml", "mode": "ro"}
        },
        restart_policy={"Name": "unless-stopped"},
        detach=True,
    )

    # Connect to networks with specific IPs
    agent_net.connect(container, ipv4_address="172.30.0.30")
    infra_net.connect(container, ipv4_address="172.31.0.30")

    return container


@app.post("/api/ssh-tunnel/start")
async def start_ssh_tunnel():
    """Start SSH tunnel by bringing up frpc container."""
    # Check if configured
    env_vars = read_env_file()
    required = ["FRP_SERVER_ADDR", "FRP_AUTH_TOKEN", "AGENT_ID", "STCP_SECRET_KEY"]
    missing = [k for k in required if not env_vars.get(k)]

    if missing:
        raise HTTPException(400, f"Missing configuration: {', '.join(missing)}. Configure tunnel first.")

    # Try to start existing container or create new one
    frpc_status = get_frpc_status()

    try:
        if frpc_status.get("exists"):
            container = docker_client.containers.get(FRPC_CONTAINER_NAME)
            if container.status != "running":
                container.start()
            return {"status": "started", "message": "FRP client container started"}
        else:
            # Container doesn't exist - create it using Docker SDK
            container = create_frpc_container(env_vars)
            container.start()
            return {"status": "started", "message": "FRP client container created and started"}
    except docker.errors.ImageNotFound:
        # Pull the image first
        docker_client.images.pull("snowdreamtech/frpc:latest")
        container = create_frpc_container(env_vars)
        container.start()
        return {"status": "started", "message": "FRP client image pulled and container started"}
    except docker.errors.APIError as e:
        raise HTTPException(500, f"Docker error: {e}")


@app.post("/api/ssh-tunnel/stop")
async def stop_ssh_tunnel():
    """Stop SSH tunnel by stopping frpc container."""
    frpc_status = get_frpc_status()

    if not frpc_status.get("exists"):
        return {"status": "ok", "message": "Tunnel not running"}

    try:
        container = docker_client.containers.get(FRPC_CONTAINER_NAME)
        container.stop(timeout=10)
        return {"status": "stopped", "message": "FRP client container stopped"}
    except docker.errors.NotFound:
        return {"status": "ok", "message": "Container not found"}
    except Exception as e:
        raise HTTPException(500, f"Failed to stop container: {e}")


@app.get("/api/ssh-tunnel/connect-info")
async def get_connect_info():
    """Get SSH connection info for this agent."""
    env_vars = read_env_file()

    if not env_vars.get("STCP_SECRET_KEY"):
        raise HTTPException(400, "Tunnel not configured")

    agent_id = env_vars.get("AGENT_ID", "default")
    secret_key = env_vars.get("STCP_SECRET_KEY")
    frp_server = env_vars.get("FRP_SERVER_ADDR")
    frp_port = env_vars.get("FRP_SERVER_PORT", "7000")

    # Generate frpc visitor config for connecting
    visitor_config = f"""# FRP Visitor Configuration - Save as frpc-visitor.toml
# Run: frpc -c frpc-visitor.toml
serverAddr = "{frp_server}"
serverPort = {frp_port}
auth.method = "token"
auth.token = "<YOUR_FRP_AUTH_TOKEN>"

[[visitors]]
name = "{agent_id}-ssh-visitor"
type = "stcp"
serverName = "{agent_id}-ssh"
secretKey = "{secret_key}"
bindAddr = "127.0.0.1"
bindPort = 2222
"""

    return {
        "agent_id": agent_id,
        "frp_server": frp_server,
        "frp_port": frp_port,
        "stcp_secret_key": secret_key,
        "ssh_command": f"ssh -p 2222 agent@127.0.0.1  # After starting visitor",
        "visitor_config": visitor_config
    }


# =============================================================================
# Static files (frontend)
# =============================================================================

# Serve frontend static files in production
FRONTEND_DIR = Path(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        """Serve frontend for all non-API routes."""
        if path.startswith("api/"):
            raise HTTPException(404)

        file_path = FRONTEND_DIR / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(FRONTEND_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
