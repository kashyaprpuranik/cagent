"""
Pytest fixtures for data-plane integration tests.
"""

import socket
import subprocess
from pathlib import Path

import pytest

# Data plane directory
DATA_PLANE_DIR = Path(__file__).parent.parent


@pytest.fixture(scope="session")
def data_plane_dir():
    """Return the data-plane directory path."""
    return DATA_PLANE_DIR


@pytest.fixture(scope="session")
def configs_dir(data_plane_dir):
    """Return the configs directory path."""
    return data_plane_dir / "configs"


def is_port_open(host: str, port: int) -> bool:
    """Check if a port is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        return result == 0


def is_docker_available() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


@pytest.fixture(scope="session")
def docker_available():
    """Check if Docker is available for container tests."""
    return is_docker_available()


@pytest.fixture
def skip_without_docker(docker_available):
    """Skip test if Docker is not available."""
    if not docker_available:
        pytest.skip("Docker not available")
