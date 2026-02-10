import os

import docker

AGENT_CONTAINER_NAME = "agent"
COREDNS_CONTAINER_NAME = "dns-filter"
ENVOY_CONTAINER_NAME = "http-proxy"
EMAIL_PROXY_CONTAINER_NAME = "email-proxy"
FRPC_CONTAINER_NAME = "tunnel-client"
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
DATA_PLANE_DIR = os.environ.get("DATA_PLANE_DIR", "/app/data_plane")
DATAPLANE_MODE = os.environ.get("DATAPLANE_MODE", "standalone")

# Read-only mode: when connected to control plane, local admin should not modify config
READ_ONLY = DATAPLANE_MODE == "connected"

docker_client = docker.from_env()

BETA_FEATURES = set(
    f.strip() for f in os.environ.get('BETA_FEATURES', '').split(',') if f.strip()
)

_base_containers = [AGENT_CONTAINER_NAME, COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME]
if "email" in BETA_FEATURES:
    _base_containers.append(EMAIL_PROXY_CONTAINER_NAME)
MANAGED_CONTAINERS = _base_containers
