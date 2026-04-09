"""Configuration from environment variables."""

import os


def get_api_url() -> str:
    return os.environ.get("CAGENT_API_URL", "https://app.cagent-control.com")


def get_api_token() -> str:
    token = os.environ.get("CAGENT_API_TOKEN", "")
    if not token:
        raise RuntimeError(
            "CAGENT_API_TOKEN environment variable is required. "
            "Create an API token at https://app.cagent-control.com/tokens"
        )
    return token
