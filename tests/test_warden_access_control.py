
import sys
import os
from unittest.mock import MagicMock, patch

# Add services/warden to sys.path so we can import main
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

from fastapi.testclient import TestClient
import pytest

# Mock docker client before importing main which imports constants which creates docker_client
mock_docker = MagicMock()
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = mock_docker
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception

# Configure list to return empty list so discover_cell_container_names returns fallback
mock_docker.containers.list.return_value = []

import main
from routers import logs as logs_module

client = TestClient(main.app)

def test_logs_access_control():
    # Setup mocks
    test_docker = MagicMock()
    test_docker.containers.list.return_value = []

    mock_container_managed = MagicMock()
    mock_container_managed.logs.return_value = b"managed logs"

    mock_container_unmanaged = MagicMock()
    mock_container_unmanaged.logs.return_value = b"secret logs"

    def get_container_side_effect(name):
        if name == "cell":
            return mock_container_managed
        elif name == "unmanaged-container":
            return mock_container_unmanaged
        else:
            raise Exception("Container not found")

    test_docker.containers.get.side_effect = get_container_side_effect

    # Patch docker_client directly in the logs module to survive test ordering
    with patch.object(logs_module, "docker_client", test_docker):
        # 1. Test unmanaged container logs
        # This should now return 403 Forbidden
        response = client.get("/api/containers/unmanaged-container/logs")
        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

        # 2. Test managed container logs
        # 'cell' is in default managed containers list because mock_docker list returns []
        response = client.get("/api/containers/cell/logs")
        assert response.status_code == 200
        assert response.json()["lines"] == ["managed logs"]
