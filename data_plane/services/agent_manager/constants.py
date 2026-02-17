"""Unified constants for agent-manager (merged from agent-manager + local-admin)."""

import os
from typing import List

import docker

# Docker client (single instance shared across the service)
docker_client = docker.from_env()

# ---------------------------------------------------------------------------
# Agent discovery
# ---------------------------------------------------------------------------
AGENT_LABEL = "cagent.role=agent"
AGENT_CONTAINER_FALLBACK = "agent"

# ---------------------------------------------------------------------------
# Infrastructure container names
# ---------------------------------------------------------------------------
COREDNS_CONTAINER_NAME = "dns-filter"
ENVOY_CONTAINER_NAME = "http-proxy"
EMAIL_PROXY_CONTAINER_NAME = "email-proxy"
AGENT_MANAGER_CONTAINER_NAME = "agent-manager"
FRPC_CONTAINER_NAME = "tunnel-client"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
COREDNS_COREFILE_PATH = os.environ.get("COREDNS_COREFILE_PATH", "/etc/coredns/Corefile")
ENVOY_CONFIG_PATH = os.environ.get("ENVOY_CONFIG_PATH", "/etc/envoy/envoy.yaml")
ENVOY_LUA_PATH = os.environ.get("ENVOY_LUA_PATH", "/etc/envoy/filter.lua")
DATA_PLANE_DIR = os.environ.get("DATA_PLANE_DIR", "/app/data_plane")

# ---------------------------------------------------------------------------
# Seccomp profiles
# ---------------------------------------------------------------------------
SECCOMP_PROFILES_DIR = os.environ.get("SECCOMP_PROFILES_DIR", "/etc/seccomp/profiles")
VALID_SECCOMP_PROFILES = {"standard", "hardened", "permissive"}

# ---------------------------------------------------------------------------
# Mode & connectivity
# ---------------------------------------------------------------------------
DATAPLANE_MODE = os.environ.get("DATAPLANE_MODE", "standalone")
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://backend:8000")
CONTROL_PLANE_TOKEN = os.environ.get("CONTROL_PLANE_TOKEN", "")

# Read-only mode: when connected to control plane, local admin should not modify config
READ_ONLY = DATAPLANE_MODE == "connected"

# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
CONFIG_SYNC_INTERVAL = int(os.environ.get("CONFIG_SYNC_INTERVAL", "300"))
MAX_HEARTBEAT_WORKERS = int(os.environ.get("HEARTBEAT_MAX_WORKERS", "20"))

# ---------------------------------------------------------------------------
# Beta features
# ---------------------------------------------------------------------------
BETA_FEATURES = set(
    f.strip() for f in os.environ.get('BETA_FEATURES', '').split(',') if f.strip()
)


# ---------------------------------------------------------------------------
# Container discovery helpers
# ---------------------------------------------------------------------------

def discover_agent_container_names() -> List[str]:
    """Return names of agent containers discovered by label.

    Falls back to the fixed name ``agent`` when no labelled containers exist.
    """
    try:
        containers = docker_client.containers.list(
            all=True,
            filters={"label": AGENT_LABEL},
        )
        if containers:
            return [c.name for c in containers]
    except Exception:
        pass
    return [AGENT_CONTAINER_FALLBACK]


def _container_exists(name: str) -> bool:
    """Check if a Docker container exists (running or stopped)."""
    try:
        docker_client.containers.get(name)
        return True
    except Exception:
        return False


def get_managed_containers() -> List[str]:
    """Build the managed-container list dynamically.

    Agent containers are discovered by label; infrastructure containers are
    static.  Optional containers (agent-manager, email-proxy) are included
    only when they actually exist.
    """
    names = discover_agent_container_names()
    names.extend([COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME])
    if _container_exists(AGENT_MANAGER_CONTAINER_NAME):
        names.append(AGENT_MANAGER_CONTAINER_NAME)
    if "email" in BETA_FEATURES:
        names.append(EMAIL_PROXY_CONTAINER_NAME)
    return names


# Backward-compat alias used by the detailed health and container routers.
AGENT_CONTAINER_NAME = discover_agent_container_names()[0]
MANAGED_CONTAINERS = get_managed_containers()
