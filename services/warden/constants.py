"""Constants for warden."""

import logging
import os
from typing import List

import docker

_logger = logging.getLogger(__name__)

# Docker client (single instance shared across the service)
docker_client = docker.from_env()

# ---------------------------------------------------------------------------
# Cell discovery
# ---------------------------------------------------------------------------
CELL_LABEL = "cagent.role=cell"
CELL_CONTAINER_FALLBACK = "cell"

# ---------------------------------------------------------------------------
# Infrastructure container names
# ---------------------------------------------------------------------------
COREDNS_CONTAINER_NAME = "dns-filter"
ENVOY_CONTAINER_NAME = "http-proxy"
MITM_PROXY_CONTAINER_NAME = "mitm-proxy"
EMAIL_PROXY_CONTAINER_NAME = "email-proxy"
WARDEN_CONTAINER_NAME = "warden"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
COREDNS_COREFILE_PATH = os.environ.get("COREDNS_COREFILE_PATH", "/etc/coredns/Corefile")
ENVOY_CONFIG_PATH = os.environ.get("ENVOY_CONFIG_PATH", "/etc/envoy/envoy.yaml")
EMAIL_CONFIG_PATH = os.environ.get("EMAIL_CONFIG_PATH", "/etc/cagent/email/accounts.json")
DATA_PLANE_DIR = os.environ.get("DATA_PLANE_DIR", "/app/cagent")
DLP_CONFIG_PATH = os.path.join(DATA_PLANE_DIR, "configs", "mitm", "dlp_config.json")

# ---------------------------------------------------------------------------
# Seccomp profiles
# ---------------------------------------------------------------------------
SECCOMP_PROFILES_DIR = os.environ.get("SECCOMP_PROFILES_DIR", "/etc/seccomp/profiles")
VALID_SECCOMP_PROFILES = {"standard", "hardened", "permissive"}

# ---------------------------------------------------------------------------
# Runtime policies — full container security postures
# ---------------------------------------------------------------------------
# Capabilities required by sshd/entrypoint (same as docker-compose cap_add)
SSHD_CAPS = [
    "CHOWN",            # entrypoint: chown on SSH keys, tmux dirs
    "DAC_OVERRIDE",     # read/write files across users during setup
    "FOWNER",           # entrypoint: chmod on SSH authorized_keys
    "SETUID",           # gosu + sshd privilege separation
    "SETGID",           # gosu + sshd privilege separation
    "NET_BIND_SERVICE", # sshd binds port 22
    "SYS_CHROOT",       # sshd privilege separation (ChrootDirectory)
    "AUDIT_WRITE",      # sshd/PAM audit logging
    "KILL",             # sshd manages child processes
]

# tmpfs mounts for read-only root (same as docker-compose tmpfs)
READONLY_TMPFS = {
    "/tmp": "size=100M",
    "/run": "size=10M",
    "/var/log": "size=50M",
    "/etc/ssh": "size=1M",
    "/home/cell": "size=10M",
    "/etc/profile.d": "size=1M",
}

VALID_RUNTIME_POLICIES = {"standard", "hardened", "permissive"}

# Shared base for hardened/standard (only seccomp filter differs)
_LOCKED_DOWN_BASE = {
    "cap_drop": ["ALL"],
    "cap_add": SSHD_CAPS,
    "read_only": True,
    "tmpfs": READONLY_TMPFS,
    "no_new_privileges": True,
}

RUNTIME_POLICIES = {
    "hardened": {"seccomp": "hardened", **_LOCKED_DOWN_BASE},
    "standard": {"seccomp": "standard", **_LOCKED_DOWN_BASE},
    "permissive": {
        "seccomp": "permissive",
        "cap_drop": ["NET_RAW"],
        "cap_add": [],
        "read_only": False,
        "tmpfs": {},
        "no_new_privileges": True,
    },
}

# ---------------------------------------------------------------------------
# Mode & connectivity
# ---------------------------------------------------------------------------
DATAPLANE_MODE = os.environ.get("DATAPLANE_MODE", "standalone")
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://backend:8000")
CONTROL_PLANE_TOKEN = os.environ.get("CONTROL_PLANE_TOKEN", "")
# Separate heartbeat URL — allows routing heartbeats to a lightweight Cloud Run
# service without --no-cpu-throttling, while critical DP traffic (policy sync,
# credential injection) stays on the main backend.  Falls back to CONTROL_PLANE_URL.
HEARTBEAT_URL = os.environ.get("HEARTBEAT_URL", "") or CONTROL_PLANE_URL

# Read-only mode: when connected to control plane, local admin should not modify config
READ_ONLY = DATAPLANE_MODE == "connected"

# Warden API auth (connected mode — CP sends requests via mTLS)
WARDEN_API_TOKEN = os.environ.get("WARDEN_API_TOKEN", "").strip()

# Local OpenObserve (per-DP log store)
OPENOBSERVE_URL = os.environ.get("OPENOBSERVE_URL", "http://log-store:5080")
OPENOBSERVE_USER = os.environ.get("OPENOBSERVE_USER", "admin@cagent.local")
OPENOBSERVE_PASSWORD = os.environ.get("OPENOBSERVE_PASSWORD", "")

# OpenTelemetry tracing (opt-in)
OTEL_ENABLED = os.environ.get("OTEL_ENABLED", "false").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# Timing
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "60"))
CONFIG_SYNC_INTERVAL = int(os.environ.get("CONFIG_SYNC_INTERVAL", "300"))
MAX_HEARTBEAT_WORKERS = int(os.environ.get("HEARTBEAT_MAX_WORKERS", "20"))

# ---------------------------------------------------------------------------
# Beta features
# ---------------------------------------------------------------------------
BETA_FEATURES = set(f.strip() for f in os.environ.get("BETA_FEATURES", "").split(",") if f.strip())


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
_default_origins = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"]
_env_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
ALLOWED_CORS_ORIGINS = list(set(_default_origins + _env_origins))

# ---------------------------------------------------------------------------
# mTLS (CP-to-DP mutual TLS)
# ---------------------------------------------------------------------------
# The control plane provisions these as base64-encoded PEM via cloud-init.
_WARDEN_TLS_CERT_B64 = os.environ.get("WARDEN_TLS_CERT", "").strip()
_WARDEN_TLS_KEY_B64 = os.environ.get("WARDEN_TLS_KEY", "").strip()
_WARDEN_MTLS_CA_CERT_B64 = os.environ.get("WARDEN_MTLS_CA_CERT", "").strip()

MTLS_ENABLED = bool(_WARDEN_TLS_CERT_B64 and _WARDEN_TLS_KEY_B64 and _WARDEN_MTLS_CA_CERT_B64)
MTLS_PORT = 8443


_temp_pem_files: List[str] = []


def _write_temp_pem(data_b64: str, suffix: str = ".pem") -> str:
    """Base64-decode *data_b64* and write to a temp file. Returns the path."""
    import base64
    import tempfile

    raw = base64.b64decode(data_b64)
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(raw)
    f.close()
    _temp_pem_files.append(f.name)
    return f.name


def _cleanup_temp_pem_files():
    """Remove temporary PEM files (especially private keys)."""
    for path in _temp_pem_files:
        try:
            os.remove(path)
        except OSError:
            pass


# Materialize cert files only when mTLS is enabled.
if MTLS_ENABLED:
    import atexit

    MTLS_CERT_PATH = _write_temp_pem(_WARDEN_TLS_CERT_B64, suffix="-cert.pem")
    MTLS_KEY_PATH = _write_temp_pem(_WARDEN_TLS_KEY_B64, suffix="-key.pem")
    MTLS_CA_CERT_PATH = _write_temp_pem(_WARDEN_MTLS_CA_CERT_B64, suffix="-ca.pem")
    atexit.register(_cleanup_temp_pem_files)
else:
    MTLS_CERT_PATH = ""
    MTLS_KEY_PATH = ""
    MTLS_CA_CERT_PATH = ""


# ---------------------------------------------------------------------------
# Container discovery helpers
# ---------------------------------------------------------------------------


def discover_cell_containers() -> List:
    """Discover cell containers by the ``cagent.role=cell`` label.

    Falls back to looking up a container named ``cell`` when no labelled
    containers are found (backward compat with unlabelled setups).

    Returns full Docker container objects.
    """
    import logging

    _logger = logging.getLogger(__name__)
    try:
        containers = docker_client.containers.list(
            all=True,
            filters={"label": CELL_LABEL},
        )
        if containers:
            return containers
    except docker.errors.APIError as e:
        _logger.warning(f"Label-based discovery failed: {e}")

    # Fallback: try the fixed name
    try:
        container = docker_client.containers.get(CELL_CONTAINER_FALLBACK)
        return [container]
    except docker.errors.NotFound:
        _logger.debug("Fallback cell container %r not found", CELL_CONTAINER_FALLBACK)
        return []
    except docker.errors.APIError as e:
        _logger.error(f"Docker API error during fallback discovery: {e}")
        return []


def discover_cell_container_names() -> List[str]:
    """Return names of cell containers discovered by label.

    Falls back to the fixed name ``cell`` when no labelled containers exist.
    """
    try:
        containers = docker_client.containers.list(
            all=True,
            filters={"label": CELL_LABEL},
        )
        if containers:
            return [c.name for c in containers]
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Label-based cell name discovery failed: %s", e)
    return [CELL_CONTAINER_FALLBACK]


def _container_exists(name: str) -> bool:
    """Check if a Docker container exists (running or stopped)."""
    try:
        docker_client.containers.get(name)
        return True
    except Exception as e:
        _logger.debug("Error checking container %r existence: %s", name, e)
        return False


def get_managed_containers() -> List[str]:
    """Build the managed-container list dynamically.

    Cell containers are discovered by label; infrastructure containers are
    static.  Optional containers (warden, email-proxy) are included
    only when they actually exist.
    """
    names = discover_cell_container_names()
    names.extend([COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME, MITM_PROXY_CONTAINER_NAME])
    if _container_exists(WARDEN_CONTAINER_NAME):
        names.append(WARDEN_CONTAINER_NAME)
    if "email" in BETA_FEATURES:
        names.append(EMAIL_PROXY_CONTAINER_NAME)
    return names


# Backward-compat alias used by the detailed health and container routers.
CELL_CONTAINER_NAME = discover_cell_container_names()[0]
MANAGED_CONTAINERS = get_managed_containers()
