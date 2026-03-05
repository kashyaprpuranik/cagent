"""Unit tests for warden mTLS configuration."""

import base64
import importlib
import os
import sys
from unittest.mock import MagicMock

import pytest

# Mock docker before importing warden modules
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = MagicMock(
    containers=MagicMock(list=MagicMock(return_value=[]))
)
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

# Sample PEM content for testing
_SAMPLE_CERT = b"-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n"
_SAMPLE_KEY = b"-----BEGIN PRIVATE KEY-----\nMIIBfake...\n-----END PRIVATE KEY-----\n"
_SAMPLE_CA = b"-----BEGIN CERTIFICATE-----\nMIIBfakeCA...\n-----END CERTIFICATE-----\n"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _reload_constants(env_overrides: dict):
    """Reload the constants module with the given env var overrides."""
    original = {}
    for k, v in env_overrides.items():
        original[k] = os.environ.get(k)
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        import constants

        importlib.reload(constants)
        return constants
    finally:
        for k, v in original.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestMtlsDisabled:
    """MTLS_ENABLED should be False when env vars are missing or partial."""

    def test_no_env_vars(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": "",
            "WARDEN_TLS_KEY": "",
            "WARDEN_MTLS_CA_CERT": "",
        })
        assert c.MTLS_ENABLED is False
        assert c.MTLS_CERT_PATH == ""
        assert c.MTLS_KEY_PATH == ""
        assert c.MTLS_CA_CERT_PATH == ""

    def test_missing_cert(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": "",
            "WARDEN_TLS_KEY": _b64(_SAMPLE_KEY),
            "WARDEN_MTLS_CA_CERT": _b64(_SAMPLE_CA),
        })
        assert c.MTLS_ENABLED is False

    def test_missing_key(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": _b64(_SAMPLE_CERT),
            "WARDEN_TLS_KEY": "",
            "WARDEN_MTLS_CA_CERT": _b64(_SAMPLE_CA),
        })
        assert c.MTLS_ENABLED is False

    def test_missing_ca(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": _b64(_SAMPLE_CERT),
            "WARDEN_TLS_KEY": _b64(_SAMPLE_KEY),
            "WARDEN_MTLS_CA_CERT": "",
        })
        assert c.MTLS_ENABLED is False

    def test_unset_env_vars(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": None,
            "WARDEN_TLS_KEY": None,
            "WARDEN_MTLS_CA_CERT": None,
        })
        assert c.MTLS_ENABLED is False


class TestMtlsEnabled:
    """MTLS_ENABLED should be True when all three env vars are set."""

    def test_enabled_when_all_set(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": _b64(_SAMPLE_CERT),
            "WARDEN_TLS_KEY": _b64(_SAMPLE_KEY),
            "WARDEN_MTLS_CA_CERT": _b64(_SAMPLE_CA),
        })
        assert c.MTLS_ENABLED is True

    def test_cert_files_contain_decoded_pem(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": _b64(_SAMPLE_CERT),
            "WARDEN_TLS_KEY": _b64(_SAMPLE_KEY),
            "WARDEN_MTLS_CA_CERT": _b64(_SAMPLE_CA),
        })
        assert c.MTLS_ENABLED is True

        with open(c.MTLS_CERT_PATH, "rb") as f:
            assert f.read() == _SAMPLE_CERT
        with open(c.MTLS_KEY_PATH, "rb") as f:
            assert f.read() == _SAMPLE_KEY
        with open(c.MTLS_CA_CERT_PATH, "rb") as f:
            assert f.read() == _SAMPLE_CA

    def test_cert_file_paths_are_nonempty(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": _b64(_SAMPLE_CERT),
            "WARDEN_TLS_KEY": _b64(_SAMPLE_KEY),
            "WARDEN_MTLS_CA_CERT": _b64(_SAMPLE_CA),
        })
        assert c.MTLS_CERT_PATH != ""
        assert c.MTLS_KEY_PATH != ""
        assert c.MTLS_CA_CERT_PATH != ""


class TestMtlsPort:
    """MTLS_PORT should always be 8443."""

    def test_port_value(self):
        c = _reload_constants({
            "WARDEN_TLS_CERT": "",
            "WARDEN_TLS_KEY": "",
            "WARDEN_MTLS_CA_CERT": "",
        })
        assert c.MTLS_PORT == 8443
