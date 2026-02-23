"""
Config loader - loads email configuration from cagent.yaml.

Resolves credential env var references to actual values.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")


@dataclass
class EmailPolicy:
    allowed_recipients: list[str] = field(default_factory=lambda: ["*"])
    allowed_senders: list[str] = field(default_factory=lambda: ["*"])
    sends_per_hour: int = 50
    reads_per_hour: int = 200


@dataclass
class EmailCredential:
    # OAuth2 fields (gmail, outlook)
    client_id: str = ""
    client_secret: str = ""
    refresh_token: str = ""
    # Password field (generic)
    password: str = ""


@dataclass
class EmailAccount:
    name: str
    provider: str  # gmail | outlook | generic
    email: str
    imap_server: str = ""
    imap_port: int = 993
    smtp_server: str = ""
    smtp_port: int = 587
    credential: EmailCredential = field(default_factory=EmailCredential)
    policy: EmailPolicy = field(default_factory=EmailPolicy)


def _resolve_env(env_name: str) -> str:
    """Resolve an environment variable name to its value."""
    if not env_name:
        return ""
    return os.environ.get(env_name, "")


def _parse_credential(cred_dict: dict) -> EmailCredential:
    """Parse credential section, resolving *_env references."""
    if not cred_dict:
        return EmailCredential()
    return EmailCredential(
        client_id=_resolve_env(cred_dict.get("client_id_env", "")),
        client_secret=_resolve_env(cred_dict.get("client_secret_env", "")),
        refresh_token=_resolve_env(cred_dict.get("refresh_token_env", "")),
        password=_resolve_env(cred_dict.get("password_env", "")),
    )


def _parse_policy(policy_dict: dict) -> EmailPolicy:
    """Parse policy section."""
    if not policy_dict:
        return EmailPolicy()
    return EmailPolicy(
        allowed_recipients=policy_dict.get("allowed_recipients", ["*"]),
        allowed_senders=policy_dict.get("allowed_senders", ["*"]),
        sends_per_hour=policy_dict.get("sends_per_hour", 50),
        reads_per_hour=policy_dict.get("reads_per_hour", 200),
    )


# Default server settings per provider
PROVIDER_DEFAULTS = {
    "gmail": {
        "imap_server": "imap.gmail.com",
        "imap_port": 993,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
    },
    "outlook": {
        "imap_server": "outlook.office365.com",
        "imap_port": 993,
        "smtp_server": "smtp.office365.com",
        "smtp_port": 587,
    },
}


def _parse_account(acct_dict: dict) -> EmailAccount:
    """Parse a single account entry."""
    provider = acct_dict.get("provider", "generic")
    defaults = PROVIDER_DEFAULTS.get(provider, {})

    return EmailAccount(
        name=acct_dict["name"],
        provider=provider,
        email=acct_dict["email"],
        imap_server=acct_dict.get("imap_server", defaults.get("imap_server", "")),
        imap_port=acct_dict.get("imap_port", defaults.get("imap_port", 993)),
        smtp_server=acct_dict.get("smtp_server", defaults.get("smtp_server", "")),
        smtp_port=acct_dict.get("smtp_port", defaults.get("smtp_port", 587)),
        credential=_parse_credential(acct_dict.get("credential", {})),
        policy=_parse_policy(acct_dict.get("policy", {})),
    )


def load_email_config(config_path: str = None) -> list[EmailAccount]:
    """Load email accounts from cagent.yaml."""
    path = Path(config_path or CAGENT_CONFIG_PATH)
    if not path.exists():
        logger.warning(f"Config file not found: {path}")
        return []

    with open(path) as f:
        config = yaml.safe_load(f)

    email_section = config.get("email", {})
    accounts_raw = email_section.get("accounts", [])

    accounts = []
    for acct_dict in accounts_raw:
        try:
            acct = _parse_account(acct_dict)
            _validate_account(acct)
            accounts.append(acct)
            logger.info(f"Loaded email account: {acct.name} ({acct.provider})")
        except Exception as e:
            logger.error(f"Failed to load email account: {e}")

    return accounts


def _validate_account(account: EmailAccount):
    """Validate account configuration."""
    if not account.name:
        raise ValueError("Account name is required")
    if not account.email:
        raise ValueError(f"Account {account.name}: email is required")
    if account.provider not in ("gmail", "outlook", "generic"):
        raise ValueError(f"Account {account.name}: provider must be gmail, outlook, or generic")
    if account.provider in ("gmail", "outlook"):
        if not account.credential.refresh_token:
            logger.warning(f"Account {account.name}: OAuth refresh_token not set (check env var)")
    if account.provider == "generic":
        if not account.credential.password:
            logger.warning(f"Account {account.name}: password not set (check env var)")
