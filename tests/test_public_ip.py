"""Tests for public IP detection (_detect_public_ip)."""

from unittest.mock import patch, MagicMock

import pytest


class TestDetectPublicIp:
    """Test _detect_public_ip() cloud metadata fallback chain."""

    def _get_detect_fn(self):
        from services.warden.main import _detect_public_ip
        return _detect_public_ip

    def test_hetzner_metadata_returns_ip(self):
        detect = self._get_detect_fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "203.0.113.10"
        with patch("services.warden.main.requests.get", return_value=mock_resp) as mock_get:
            result = detect()
            assert result == "203.0.113.10"
            # Should only call Hetzner (first match wins)
            mock_get.assert_called_once()
            assert "hetzner" in mock_get.call_args[0][0]

    def test_gce_metadata_fallback(self):
        detect = self._get_detect_fn()
        # Hetzner fails, GCE succeeds
        hetzner_resp = MagicMock()
        hetzner_resp.status_code = 404

        gce_resp = MagicMock()
        gce_resp.status_code = 200
        gce_resp.text = "35.192.0.1"

        with patch("services.warden.main.requests.get", side_effect=[hetzner_resp, gce_resp]) as mock_get:
            result = detect()
            assert result == "35.192.0.1"
            assert mock_get.call_count == 2
            # Second call should be GCE with Metadata-Flavor header
            gce_call = mock_get.call_args_list[1]
            assert "computeMetadata" in gce_call[0][0]
            assert gce_call[1]["headers"]["Metadata-Flavor"] == "Google"

    def test_all_metadata_fail_returns_none(self):
        detect = self._get_detect_fn()
        with patch("services.warden.main.requests.get", side_effect=Exception("no metadata")):
            result = detect()
            assert result is None

    def test_gce_metadata_invalid_ip_returns_none(self):
        detect = self._get_detect_fn()
        hetzner_resp = MagicMock()
        hetzner_resp.status_code = 404

        gce_resp = MagicMock()
        gce_resp.status_code = 200
        gce_resp.text = "not-an-ip"

        with patch("services.warden.main.requests.get", side_effect=[hetzner_resp, gce_resp]):
            result = detect()
            assert result is None
