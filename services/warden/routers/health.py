from datetime import datetime

from constants import (
    BETA_FEATURES,
    CAGENT_CONFIG_PATH,
    CELL_CONTAINER_NAME,
    COREDNS_CONTAINER_NAME,
    DATA_PLANE_DIR,
    DATAPLANE_MODE,
    ENVOY_CONTAINER_NAME,
    MITM_PROXY_CONTAINER_NAME,
)
from fastapi import APIRouter

router = APIRouter()


@router.api_route("/health", methods=["GET", "HEAD"])
def health():
    """Health check. Accepts HEAD for load balancer and mTLS health probes."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@router.get("/info")
def info():
    """System info."""
    containers = {
        "cell": CELL_CONTAINER_NAME,
        "dns": COREDNS_CONTAINER_NAME,
        "http_proxy": ENVOY_CONTAINER_NAME,
        "mitm_proxy": MITM_PROXY_CONTAINER_NAME,
    }
    return {
        "mode": DATAPLANE_MODE,
        "config_path": CAGENT_CONFIG_PATH,
        "data_plane_dir": DATA_PLANE_DIR,
        "features": sorted(BETA_FEATURES),
        "containers": containers,
    }
