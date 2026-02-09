import secrets
from pathlib import Path

import docker
from fastapi import APIRouter, HTTPException

from ..constants import FRPC_CONTAINER_NAME, DATA_PLANE_DIR, docker_client
from ..models import SshTunnelConfig

router = APIRouter()


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


def get_tunnel_client_status() -> dict:
    """Get tunnel client container status."""
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


@router.get("/ssh-tunnel")
async def get_ssh_tunnel_status():
    """Get SSH tunnel status and configuration."""
    env_vars = read_env_file()
    tunnel_status = get_tunnel_client_status()

    return {
        "enabled": tunnel_status.get("exists", False) and tunnel_status.get("status") == "running",
        "connected": tunnel_status.get("status") == "running",
        "stcp_proxy_name": env_vars.get("STCP_PROXY_NAME"),
        "frp_server": env_vars.get("FRP_SERVER_ADDR"),
        "frp_server_port": env_vars.get("FRP_SERVER_PORT", "7000"),
        "container_status": tunnel_status.get("status"),
        "stcp_secret_key": env_vars.get("STCP_SECRET_KEY"),
        "configured": bool(env_vars.get("FRP_SERVER_ADDR") and env_vars.get("STCP_SECRET_KEY"))
    }


@router.post("/ssh-tunnel/generate-key")
async def generate_stcp_key():
    """Generate a new STCP secret key."""
    key = secrets.token_urlsafe(32)
    return {"stcp_secret_key": key}


@router.post("/ssh-tunnel/configure")
async def configure_ssh_tunnel(config: SshTunnelConfig):
    """Configure SSH tunnel with FRP settings."""
    # Generate secret key if not provided
    stcp_key = config.stcp_secret_key or secrets.token_urlsafe(32)

    # Update .env file
    env_updates = {
        "FRP_SERVER_ADDR": config.frp_server_addr,
        "FRP_SERVER_PORT": str(config.frp_server_port),
        "FRP_AUTH_TOKEN": config.frp_auth_token,
        "STCP_PROXY_NAME": config.stcp_proxy_name,
        "STCP_SECRET_KEY": stcp_key
    }

    try:
        write_env_file(env_updates)
    except Exception as e:
        raise HTTPException(500, f"Failed to write .env file: {e}")

    return {
        "status": "configured",
        "stcp_proxy_name": config.stcp_proxy_name,
        "stcp_secret_key": stcp_key,
        "message": "Configuration saved. Use start endpoint to enable tunnel."
    }


def create_tunnel_client_container(env_vars: dict):
    """Create the tunnel client container using Docker SDK."""
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
            "STCP_PROXY_NAME": env_vars.get("STCP_PROXY_NAME"),
            "STCP_SECRET_KEY": env_vars.get("STCP_SECRET_KEY"),
        },
        volumes={
            f"{DATA_PLANE_DIR}/configs/frpc/frpc.toml": {"bind": "/etc/frp/frpc.toml", "mode": "ro"}
        },
        restart_policy={"Name": "unless-stopped"},
        detach=True,
    )

    # Connect to networks with specific IPs
    agent_net.connect(container, ipv4_address="10.200.1.30")
    infra_net.connect(container, ipv4_address="10.200.2.30")

    return container


@router.post("/ssh-tunnel/start")
async def start_ssh_tunnel():
    """Start SSH tunnel by bringing up tunnel client container."""
    # Check if configured
    env_vars = read_env_file()
    required = ["FRP_SERVER_ADDR", "FRP_AUTH_TOKEN", "STCP_PROXY_NAME", "STCP_SECRET_KEY"]
    missing = [k for k in required if not env_vars.get(k)]

    if missing:
        raise HTTPException(400, f"Missing configuration: {', '.join(missing)}. Configure tunnel first.")

    # Try to start existing container or create new one
    tunnel_status = get_tunnel_client_status()

    try:
        if tunnel_status.get("exists"):
            container = docker_client.containers.get(FRPC_CONTAINER_NAME)
            if container.status != "running":
                container.start()
            return {"status": "started", "message": "Tunnel client container started"}
        else:
            # Container doesn't exist - create it using Docker SDK
            container = create_tunnel_client_container(env_vars)
            container.start()
            return {"status": "started", "message": "Tunnel client container created and started"}
    except docker.errors.ImageNotFound:
        # Pull the image first
        docker_client.images.pull("snowdreamtech/frpc:latest")
        container = create_tunnel_client_container(env_vars)
        container.start()
        return {"status": "started", "message": "Tunnel client image pulled and container started"}
    except docker.errors.APIError as e:
        raise HTTPException(500, f"Docker error: {e}")


@router.post("/ssh-tunnel/stop")
async def stop_ssh_tunnel():
    """Stop SSH tunnel by stopping tunnel client container."""
    tunnel_status = get_tunnel_client_status()

    if not tunnel_status.get("exists"):
        return {"status": "ok", "message": "Tunnel not running"}

    try:
        container = docker_client.containers.get(FRPC_CONTAINER_NAME)
        container.stop(timeout=10)
        return {"status": "stopped", "message": "Tunnel client container stopped"}
    except docker.errors.NotFound:
        return {"status": "ok", "message": "Container not found"}
    except Exception as e:
        raise HTTPException(500, f"Failed to stop container: {e}")


@router.get("/ssh-tunnel/connect-info")
async def get_connect_info():
    """Get SSH connection info for this agent."""
    env_vars = read_env_file()

    if not env_vars.get("STCP_SECRET_KEY"):
        raise HTTPException(400, "Tunnel not configured")

    proxy_name = env_vars.get("STCP_PROXY_NAME")
    secret_key = env_vars.get("STCP_SECRET_KEY")
    frp_server = env_vars.get("FRP_SERVER_ADDR")
    frp_port = env_vars.get("FRP_SERVER_PORT", "7000")

    if not proxy_name:
        raise HTTPException(400, "STCP_PROXY_NAME not configured. Run setup_ssh_tunnel.sh first.")

    # Generate frpc visitor config for connecting
    visitor_config = f"""# FRP Visitor Configuration - Save as frpc-visitor.toml
# Run: frpc -c frpc-visitor.toml
serverAddr = "{frp_server}"
serverPort = {frp_port}
auth.method = "token"
auth.token = "<YOUR_FRP_AUTH_TOKEN>"

[[visitors]]
name = "{proxy_name}-visitor"
type = "stcp"
serverName = "{proxy_name}"
secretKey = "{secret_key}"
bindAddr = "127.0.0.1"
bindPort = 2222
"""

    return {
        "stcp_proxy_name": proxy_name,
        "frp_server": frp_server,
        "frp_port": frp_port,
        "stcp_secret_key": secret_key,
        "ssh_command": "ssh -p 2222 agent@127.0.0.1  # After starting visitor",
        "visitor_config": visitor_config
    }
