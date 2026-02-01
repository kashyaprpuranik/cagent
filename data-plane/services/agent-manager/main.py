"""
Agent Manager - Polls control plane for commands, manages agent container.

Runs as a background service that:
1. Sends heartbeat to control plane every 30s with agent status
2. Receives any pending commands (wipe, restart, stop, start)
3. Executes commands and reports results on next heartbeat
4. Syncs allowlist from control plane to CoreDNS (every 5 minutes)

No inbound ports required - only outbound to control plane.
"""

import os
import sys
import time
import json
import logging
from datetime import datetime
from typing import Optional
from pathlib import Path

import docker
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane-api:8000")
CONTROL_PLANE_TOKEN = os.environ.get("CONTROL_PLANE_TOKEN", "")
AGENT_CONTAINER_NAME = os.environ.get("AGENT_CONTAINER_NAME", "agent")
AGENT_WORKSPACE_VOLUME = os.environ.get("AGENT_WORKSPACE_VOLUME", "data-plane_agent-workspace")
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
AGENT_ID = os.environ.get("AGENT_ID", "default")

# Allowlist sync configuration
ALLOWLIST_SYNC_INTERVAL = int(os.environ.get("ALLOWLIST_SYNC_INTERVAL", "300"))  # 5 minutes
COREDNS_ALLOWLIST_PATH = os.environ.get("COREDNS_ALLOWLIST_PATH", "/etc/coredns/allowlist.hosts")
STATIC_ALLOWLIST_PATH = os.environ.get("STATIC_ALLOWLIST_PATH", "/etc/coredns/static-allowlist.hosts")

# Docker client
docker_client = docker.from_env()

# Track last command result to report on next heartbeat
last_command_result = {
    "command": None,
    "result": None,
    "message": None
}


def get_agent_container():
    """Get the agent container by name."""
    try:
        return docker_client.containers.get(AGENT_CONTAINER_NAME)
    except docker.errors.NotFound:
        return None
    except docker.errors.APIError as e:
        logger.error(f"Docker API error: {e}")
        return None


def get_agent_status() -> dict:
    """Get current agent container status."""
    container = get_agent_container()

    if not container:
        return {
            "status": "not_found",
            "container_id": None,
            "uptime_seconds": None,
            "cpu_percent": None,
            "memory_mb": None,
            "memory_limit_mb": None
        }

    container.reload()

    # Calculate uptime
    uptime_seconds = None
    if container.status == "running":
        started_at = container.attrs["State"]["StartedAt"]
        try:
            start_time = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            uptime_seconds = int((datetime.now(start_time.tzinfo) - start_time).total_seconds())
        except Exception:
            pass

    # Get resource stats
    cpu_percent = None
    memory_mb = None
    memory_limit_mb = None

    if container.status == "running":
        try:
            stats = container.stats(stream=False)

            # CPU calculation
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                       stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                          stats["precpu_stats"]["system_cpu_usage"]
            num_cpus = stats["cpu_stats"].get("online_cpus", 1)

            if system_delta > 0:
                cpu_percent = round((cpu_delta / system_delta) * num_cpus * 100, 2)

            # Memory calculation
            memory_usage = stats["memory_stats"].get("usage", 0)
            memory_limit = stats["memory_stats"].get("limit", 0)
            memory_mb = round(memory_usage / (1024 * 1024), 2)
            memory_limit_mb = round(memory_limit / (1024 * 1024), 2)

        except Exception as e:
            logger.warning(f"Could not get container stats: {e}")

    return {
        "status": container.status,
        "container_id": container.short_id,
        "uptime_seconds": uptime_seconds,
        "cpu_percent": cpu_percent,
        "memory_mb": memory_mb,
        "memory_limit_mb": memory_limit_mb
    }


def execute_command(command: str, args: Optional[dict] = None) -> tuple:
    """Execute a command and return (success, message)."""
    global last_command_result

    logger.info(f"Executing command: {command} with args: {args}")

    try:
        if command == "restart":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"
            container.restart(timeout=10)
            return True, "Agent container restarted"

        elif command == "stop":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"
            container.stop(timeout=10)
            return True, "Agent container stopped"

        elif command == "start":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"
            container.start()
            return True, "Agent container started"

        elif command == "wipe":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"

            wipe_workspace = args.get("wipe_workspace", False) if args else False

            # Stop and remove container
            if container.status == "running":
                container.stop(timeout=10)
            container.remove(force=True)

            # Optionally wipe workspace
            if wipe_workspace:
                try:
                    docker_client.containers.run(
                        "alpine:latest",
                        command="rm -rf /workspace/*",
                        volumes={AGENT_WORKSPACE_VOLUME: {"bind": "/workspace", "mode": "rw"}},
                        remove=True
                    )
                    logger.info(f"Cleared workspace volume {AGENT_WORKSPACE_VOLUME}")
                except Exception as e:
                    logger.warning(f"Could not wipe workspace: {e}")

            return True, f"Agent wiped (workspace={'wiped' if wipe_workspace else 'preserved'})"

        else:
            return False, f"Unknown command: {command}"

    except docker.errors.APIError as e:
        logger.error(f"Docker API error executing {command}: {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Error executing {command}: {e}")
        return False, str(e)


COREDNS_CONTAINER_NAME = os.environ.get("COREDNS_CONTAINER_NAME", "dns-filter")
COREDNS_COREFILE_PATH = os.environ.get("COREDNS_COREFILE_PATH", "/etc/coredns/Corefile")

# Template for generated Corefile
COREFILE_TEMPLATE = """# =============================================================================
# CoreDNS Configuration - Auto-generated by agent-manager
# Last sync: {timestamp}
# =============================================================================

# Health check and metrics
. {{
    health :8080
    prometheus :9153
    log . {{
        class all
    }}
    errors
}}

# Internal devbox.local domains -> Envoy proxy
*.devbox.local {{
    forward . 172.30.0.10
    log
}}

# Allowlisted domains - forward to upstream DNS
{domain_blocks}

# Block everything else with NXDOMAIN
. {{
    log . {{
        class denial
    }}
    template ANY ANY {{
        rcode NXDOMAIN
    }}
}}
"""

DOMAIN_BLOCK_TEMPLATE = """{domain} {{
    forward . 8.8.8.8 8.8.4.4
    cache 300
    log
}}
"""


def generate_corefile(domains: list) -> str:
    """Generate CoreDNS Corefile from list of allowed domains."""
    domain_blocks = "\n".join(
        DOMAIN_BLOCK_TEMPLATE.format(domain=d) for d in sorted(domains)
    )
    return COREFILE_TEMPLATE.format(
        timestamp=datetime.utcnow().isoformat() + "Z",
        domain_blocks=domain_blocks
    )


def restart_coredns():
    """Restart CoreDNS container to pick up new allowlist."""
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        container.restart(timeout=10)
        logger.info("Restarted CoreDNS to apply new allowlist")
        return True
    except docker.errors.NotFound:
        logger.warning(f"CoreDNS container '{COREDNS_CONTAINER_NAME}' not found")
        return False
    except Exception as e:
        logger.error(f"Failed to restart CoreDNS: {e}")
        return False


def sync_allowlist() -> bool:
    """Fetch allowlist from control plane and regenerate CoreDNS Corefile.

    Returns True if allowlist was updated, False otherwise.
    """
    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        logger.debug("Control plane not configured, skipping allowlist sync")
        return False

    try:
        response = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/allowlist/export",
            params={"entry_type": "domain", "format": "hosts"},
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10
        )

        if response.status_code != 200:
            logger.warning(f"Failed to fetch allowlist: {response.status_code}")
            return False

        cp_domains = response.text.strip()

        # Read static allowlist (fallback domains)
        static_domains = ""
        static_path = Path(STATIC_ALLOWLIST_PATH)
        if static_path.exists():
            static_domains = static_path.read_text().strip()

        # Merge: CP domains + static domains (unique, sorted)
        all_domains = set()
        for line in cp_domains.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                all_domains.add(line)
        for line in static_domains.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                all_domains.add(line)

        # Generate new Corefile
        new_corefile = generate_corefile(list(all_domains))

        # Check if changed (compare domain list only)
        corefile_path = Path(COREDNS_COREFILE_PATH)
        if corefile_path.exists():
            current_content = corefile_path.read_text()
            # Extract domain blocks from current file for comparison
            # Simple check: if same number of domains and same set, skip
            current_domains = set()
            for line in current_content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and line.endswith(" {"):
                    domain = line.rstrip(" {").strip()
                    if domain and domain != "." and not domain.startswith("*"):
                        current_domains.add(domain)
            if current_domains == all_domains:
                logger.debug("Allowlist unchanged")
                return False

        # Write new Corefile
        corefile_path.parent.mkdir(parents=True, exist_ok=True)
        corefile_path.write_text(new_corefile)
        logger.info(f"Updated CoreDNS Corefile with {len(all_domains)} allowed domains")

        # Also write allowlist.hosts for reference
        allowlist_path = Path(COREDNS_ALLOWLIST_PATH)
        allowlist_content = "# Auto-generated from Control Plane + static config\n"
        allowlist_content += f"# Last sync: {datetime.utcnow().isoformat()}Z\n"
        allowlist_content += "\n".join(sorted(all_domains))
        allowlist_content += "\n"
        allowlist_path.write_text(allowlist_content)

        # Restart CoreDNS to pick up changes
        restart_coredns()

        return True

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not reach control plane for allowlist: {e}")
        return False
    except Exception as e:
        logger.error(f"Error syncing allowlist: {e}")
        return False


def send_heartbeat() -> Optional[dict]:
    """Send heartbeat to control plane, return any pending command."""
    global last_command_result

    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        logger.warning("Control plane URL or token not configured, skipping heartbeat")
        return None

    status = get_agent_status()

    heartbeat = {
        "agent_id": AGENT_ID,
        "status": status["status"],
        "container_id": status["container_id"],
        "uptime_seconds": status["uptime_seconds"],
        "cpu_percent": status["cpu_percent"],
        "memory_mb": status["memory_mb"],
        "memory_limit_mb": status["memory_limit_mb"],
    }

    # Include last command result if any
    if last_command_result["command"]:
        heartbeat["last_command"] = last_command_result["command"]
        heartbeat["last_command_result"] = last_command_result["result"]
        heartbeat["last_command_message"] = last_command_result["message"]
        # Clear after sending
        last_command_result = {"command": None, "result": None, "message": None}

    try:
        response = requests.post(
            f"{CONTROL_PLANE_URL}/api/v1/agent/heartbeat",
            json=heartbeat,
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401 or response.status_code == 403:
            logger.error(f"Authentication failed: {response.status_code}")
            return None
        else:
            logger.warning(f"Heartbeat failed: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not reach control plane: {e}")
        return None


def main_loop():
    """Main loop: send heartbeat, execute commands, sync allowlist."""
    global last_command_result

    logger.info(f"Agent manager starting")
    logger.info(f"  Agent ID: {AGENT_ID}")
    logger.info(f"  Control plane: {CONTROL_PLANE_URL}")
    logger.info(f"  Agent container: {AGENT_CONTAINER_NAME}")
    logger.info(f"  Heartbeat interval: {HEARTBEAT_INTERVAL}s")
    logger.info(f"  Allowlist sync interval: {ALLOWLIST_SYNC_INTERVAL}s")

    if not CONTROL_PLANE_TOKEN:
        logger.warning("CONTROL_PLANE_TOKEN not set - heartbeats will fail")

    # Track time since last allowlist sync
    last_allowlist_sync = 0
    heartbeat_count = 0

    # Initial allowlist sync
    sync_allowlist()

    while True:
        try:
            # Send heartbeat and get any pending command
            response = send_heartbeat()

            if response and response.get("command"):
                command = response["command"]
                args = response.get("command_args")

                logger.info(f"Received command: {command}")

                # Execute the command
                success, message = execute_command(command, args)

                # Store result to report on next heartbeat
                last_command_result = {
                    "command": command,
                    "result": "success" if success else "failed",
                    "message": message
                }

                logger.info(f"Command {command} {'succeeded' if success else 'failed'}: {message}")

            # Sync allowlist periodically
            heartbeat_count += 1
            elapsed_since_sync = heartbeat_count * HEARTBEAT_INTERVAL
            if elapsed_since_sync >= ALLOWLIST_SYNC_INTERVAL:
                sync_allowlist()
                heartbeat_count = 0

        except Exception as e:
            logger.error(f"Error in main loop: {e}")

        # Wait for next heartbeat
        time.sleep(HEARTBEAT_INTERVAL)


if __name__ == "__main__":
    try:
        # Verify Docker connection
        docker_client.ping()
        logger.info("Docker connection verified")
    except Exception as e:
        logger.error(f"Cannot connect to Docker: {e}")
        sys.exit(1)

    main_loop()
