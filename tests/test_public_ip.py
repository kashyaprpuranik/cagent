"""Tests for public IP detection (_detect_public_ip)."""

from unittest.mock import patch, MagicMock

import pytest


class TestDetectPublicIp:
    """Test _detect_public_ip() with CLOUD_PROVIDER env var."""

    def _get_detect_fn(self):
        from services.warden.main import _detect_public_ip
        return _detect_public_ip

    def test_hetzner_metadata_returns_ip(self):
        detect = self._get_detect_fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "203.0.113.10"
        with patch.dict("os.environ", {"CLOUD_PROVIDER": "hetzner"}):
            with patch("services.warden.main.requests.get", return_value=mock_resp) as mock_get:
                result = detect()
                assert result == "203.0.113.10"
                mock_get.assert_called_once()
                assert "hetzner" in mock_get.call_args[0][0]

    def test_gce_metadata_returns_ip(self):
        detect = self._get_detect_fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "35.192.0.1"
        with patch.dict("os.environ", {"CLOUD_PROVIDER": "gce"}):
            with patch("services.warden.main.requests.get", return_value=mock_resp) as mock_get:
                result = detect()
                assert result == "35.192.0.1"
                mock_get.assert_called_once()
                assert "computeMetadata" in mock_get.call_args[0][0]
                assert mock_get.call_args[1]["headers"]["Metadata-Flavor"] == "Google"

    def test_no_cloud_provider_returns_none(self):
        detect = self._get_detect_fn()
        with patch.dict("os.environ", {}, clear=False):
            # Remove CLOUD_PROVIDER if set
            import os
            env = os.environ.copy()
            env.pop("CLOUD_PROVIDER", None)
            with patch.dict("os.environ", env, clear=True):
                result = detect()
                assert result is None

    def test_metadata_failure_returns_none(self):
        detect = self._get_detect_fn()
        with patch.dict("os.environ", {"CLOUD_PROVIDER": "hetzner"}):
            with patch("services.warden.main.requests.get", side_effect=Exception("no metadata")):
                result = detect()
                assert result is None

    def test_invalid_ip_returns_none(self):
        detect = self._get_detect_fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "not-an-ip"
        with patch.dict("os.environ", {"CLOUD_PROVIDER": "gce"}):
            with patch("services.warden.main.requests.get", return_value=mock_resp):
                result = detect()
                assert result is None

    def test_unknown_cloud_provider_returns_none(self):
        detect = self._get_detect_fn()
        with patch.dict("os.environ", {"CLOUD_PROVIDER": "aws"}):
            result = detect()
            assert result is None
