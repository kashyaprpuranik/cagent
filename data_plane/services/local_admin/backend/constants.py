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

MANAGED_CONTAINERS = [AGENT_CONTAINER_NAME, COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME, EMAIL_PROXY_CONTAINER_NAME]
