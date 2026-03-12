"""
Tests for DLP config sync integration in config_sync.py.

Verifies:
- _cp_dlp_policy_to_config converter
- regenerate_configs with additional_dlp_config
- Hash-based change detection for DLP config
- restart_mitm_proxy called only when hash changes
- Standalone mode uses local defaults
- Connected mode merges CP config
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Patch heavy dependencies before importing warden modules
# ---------------------------------------------------------------------------
# docker is not installed in the test environment — must mock before import
mock_docker = MagicMock()
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = mock_docker
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception
mock_docker.containers.list.return_value = []

WARDEN_DIR = Path(__file__).resolve().parent.parent / "services" / "warden"
sys.path.insert(0, str(WARDEN_DIR))


# ---------------------------------------------------------------------------
# _cp_dlp_policy_to_config
# ---------------------------------------------------------------------------

class TestCpDlpPolicyToConfig:

    def test_full_policy(self):
        from config_sync import _cp_dlp_policy_to_config

        policy = {
            "enabled": True,
            "mode": "block",
            "skip_domains": ["api.openai.com"],
            "custom_patterns": [{"name": "tok", "regex": r"TOK_[A-Z]+"}],
        }
        result = _cp_dlp_policy_to_config(policy)
        assert result["enabled"] is True
        assert result["mode"] == "block"
        assert result["skip_domains"] == ["api.openai.com"]
        assert len(result["custom_patterns"]) == 1

    def test_partial_policy(self):
        from config_sync import _cp_dlp_policy_to_config

        policy = {"enabled": True}
        result = _cp_dlp_policy_to_config(policy)
        assert result == {"enabled": True}

    def test_invalid_mode_defaults_to_log(self):
        from config_sync import _cp_dlp_policy_to_config

        policy = {"mode": "destroy"}
        result = _cp_dlp_policy_to_config(policy)
        assert result["mode"] == "log"

    def test_empty_policy(self):
        from config_sync import _cp_dlp_policy_to_config

        result = _cp_dlp_policy_to_config({})
        assert result == {}

    def test_custom_patterns_with_threshold(self):
        from config_sync import _cp_dlp_policy_to_config

        policy = {
            "enabled": True,
            "custom_patterns": [
                {"name": "email_bulk", "regex": "[a-z]+@[a-z]+\\.[a-z]+", "threshold": 5},
            ],
        }
        result = _cp_dlp_policy_to_config(policy)
        assert result["custom_patterns"][0]["threshold"] == 5


# ---------------------------------------------------------------------------
# ConfigGenerator DLP methods
# ---------------------------------------------------------------------------

class TestConfigGeneratorDlp:

    def test_get_dlp_config_defaults(self):
        from config_generator import ConfigGenerator, DEFAULT_DLP_PATTERNS

        gen = ConfigGenerator("/nonexistent.yaml")
        cfg = gen.get_dlp_config()
        assert cfg["enabled"] is False
        assert cfg["mode"] == "log"
        assert len(cfg["custom_patterns"]) == len(DEFAULT_DLP_PATTERNS)
        names = [p["name"] for p in cfg["custom_patterns"]]
        assert "aws_access_key" in names
        assert "ssn" in names

    def test_get_dlp_config_with_cp_override(self):
        from config_generator import ConfigGenerator

        gen = ConfigGenerator("/nonexistent.yaml")
        cp_cfg = {"enabled": True, "mode": "block", "skip_domains": [], "custom_patterns": []}
        gen.set_additional_dlp_config(cp_cfg)
        assert gen.get_dlp_config() is cp_cfg

    def test_generate_dlp_config_json(self):
        from config_generator import ConfigGenerator

        gen = ConfigGenerator("/nonexistent.yaml")
        gen.set_additional_dlp_config({"enabled": True, "mode": "redact", "skip_domains": [], "custom_patterns": []})
        result = json.loads(gen.generate_dlp_config())
        assert result["enabled"] is True
        assert result["mode"] == "redact"

    def test_write_dlp_config(self, tmp_path):
        from config_generator import ConfigGenerator

        gen = ConfigGenerator("/nonexistent.yaml")
        gen.set_additional_dlp_config({"enabled": True, "mode": "log", "skip_domains": [], "custom_patterns": []})
        out = tmp_path / "dlp_config.json"
        assert gen.write_dlp_config(str(out)) is True
        written = json.loads(out.read_text())
        assert written["enabled"] is True

    def test_set_none_falls_back_to_defaults(self):
        from config_generator import ConfigGenerator, DEFAULT_DLP_PATTERNS

        gen = ConfigGenerator("/nonexistent.yaml")
        gen.set_additional_dlp_config(None)
        cfg = gen.get_dlp_config()
        assert cfg["enabled"] is False
        assert len(cfg["custom_patterns"]) == len(DEFAULT_DLP_PATTERNS)

    def test_defaults_include_threshold_patterns(self):
        from config_generator import DEFAULT_DLP_PATTERNS

        threshold_patterns = [p for p in DEFAULT_DLP_PATTERNS if "threshold" in p]
        assert len(threshold_patterns) >= 2
        names = [p["name"] for p in threshold_patterns]
        assert "email_bulk" in names
        assert "phone_bulk" in names


# ---------------------------------------------------------------------------
# regenerate_configs DLP integration
# ---------------------------------------------------------------------------

class TestRegenerateConfigsDlp:

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        """Create a minimal cagent.yaml and patch paths."""
        self.yaml_path = tmp_path / "cagent.yaml"
        self.yaml_path.write_text("domains:\n  - domain: example.com\n")
        self.corefile_path = tmp_path / "Corefile"
        self.envoy_path = tmp_path / "envoy.yaml"
        self.email_path = tmp_path / "accounts.json"
        self.dlp_path = tmp_path / "dlp_config.json"
        self.env_path = tmp_path / ".env"

    @patch("config_sync.restart_mitm_proxy")
    @patch("config_sync.reload_email_proxy")
    @patch("config_sync.reload_envoy")
    @patch("config_sync.restart_coredns")
    def test_dlp_config_triggers_mitm_restart(self, mock_dns, mock_envoy, mock_email, mock_mitm):
        from config_sync import ConfigState, config_generator, regenerate_configs

        # Point generator at our temp yaml
        config_generator.config_path = self.yaml_path

        # Patch output paths
        with patch("config_sync.COREDNS_COREFILE_PATH", str(self.corefile_path)), \
             patch("config_sync.ENVOY_CONFIG_PATH", str(self.envoy_path)), \
             patch("config_sync.EMAIL_CONFIG_PATH", str(self.email_path)), \
             patch("config_sync.DLP_CONFIG_PATH", str(self.dlp_path)), \
             patch("config_sync.ENV_FILE_PATH", str(self.env_path)), \
             patch("config_sync.config_state", ConfigState()), \
             patch("routers.domain_policy.invalidate_cache", MagicMock()), \
             patch("routers.ext_authz.invalidate_cache", MagicMock()):

            dlp_cfg = {"enabled": True, "mode": "block", "skip_domains": [], "custom_patterns": []}
            result = regenerate_configs(additional_dlp_config=dlp_cfg)
            assert result is True
            mock_mitm.assert_called_once()

            # Verify DLP config was written
            written = json.loads(self.dlp_path.read_text())
            assert written["enabled"] is True
            assert written["mode"] == "block"

    @patch("config_sync.restart_mitm_proxy")
    @patch("config_sync.reload_email_proxy")
    @patch("config_sync.reload_envoy")
    @patch("config_sync.restart_coredns")
    def test_dlp_no_restart_when_unchanged(self, mock_dns, mock_envoy, mock_email, mock_mitm):
        from config_sync import ConfigState, config_generator, regenerate_configs, _stable_hash

        config_generator.config_path = self.yaml_path

        state = ConfigState()

        with patch("config_sync.COREDNS_COREFILE_PATH", str(self.corefile_path)), \
             patch("config_sync.ENVOY_CONFIG_PATH", str(self.envoy_path)), \
             patch("config_sync.EMAIL_CONFIG_PATH", str(self.email_path)), \
             patch("config_sync.DLP_CONFIG_PATH", str(self.dlp_path)), \
             patch("config_sync.ENV_FILE_PATH", str(self.env_path)), \
             patch("config_sync.config_state", state), \
             patch("routers.domain_policy.invalidate_cache", MagicMock()), \
             patch("routers.ext_authz.invalidate_cache", MagicMock()):

            dlp_cfg = {"enabled": True, "mode": "block", "skip_domains": [], "custom_patterns": []}

            # First call: writes config
            regenerate_configs(additional_dlp_config=dlp_cfg)
            mock_mitm.assert_called_once()
            mock_mitm.reset_mock()

            # Second call with same config: no restart
            regenerate_configs(additional_dlp_config=dlp_cfg)
            mock_mitm.assert_not_called()

    @patch("config_sync.restart_mitm_proxy")
    @patch("config_sync.reload_email_proxy")
    @patch("config_sync.reload_envoy")
    @patch("config_sync.restart_coredns")
    def test_standalone_mode_no_dlp_override(self, mock_dns, mock_envoy, mock_email, mock_mitm):
        from config_sync import ConfigState, config_generator, regenerate_configs

        config_generator.config_path = self.yaml_path

        with patch("config_sync.COREDNS_COREFILE_PATH", str(self.corefile_path)), \
             patch("config_sync.ENVOY_CONFIG_PATH", str(self.envoy_path)), \
             patch("config_sync.EMAIL_CONFIG_PATH", str(self.email_path)), \
             patch("config_sync.DLP_CONFIG_PATH", str(self.dlp_path)), \
             patch("config_sync.ENV_FILE_PATH", str(self.env_path)), \
             patch("config_sync.config_state", ConfigState()), \
             patch("routers.domain_policy.invalidate_cache", MagicMock()), \
             patch("routers.ext_authz.invalidate_cache", MagicMock()):

            # No additional_dlp_config -> standalone defaults
            result = regenerate_configs()
            assert result is True

            written = json.loads(self.dlp_path.read_text())
            assert written["enabled"] is False
            assert written["mode"] == "log"
            # Standalone defaults include all built-in patterns
            assert len(written["custom_patterns"]) > 0


# ---------------------------------------------------------------------------
# restart_mitm_proxy
# ---------------------------------------------------------------------------

class TestRestartMitmProxy:

    @patch("config_sync.docker_client")
    def test_restart_success(self, mock_client):
        from config_sync import restart_mitm_proxy

        mock_container = MagicMock()
        mock_client.containers.get.return_value = mock_container
        assert restart_mitm_proxy() is True
        mock_container.restart.assert_called_once_with(timeout=10)

    @patch("config_sync.docker_client")
    def test_restart_not_found(self, mock_client):
        from config_sync import restart_mitm_proxy

        # docker.errors.NotFound is mocked as Exception at module level
        mock_client.containers.get.side_effect = sys.modules["docker"].errors.NotFound("not found")
        assert restart_mitm_proxy() is False

    @patch("config_sync.docker_client")
    def test_restart_generic_error(self, mock_client):
        from config_sync import restart_mitm_proxy

        mock_client.containers.get.side_effect = RuntimeError("boom")
        assert restart_mitm_proxy() is False
