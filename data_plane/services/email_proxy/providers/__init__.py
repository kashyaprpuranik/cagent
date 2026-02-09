from .gmail import GmailProvider
from .outlook import OutlookProvider
from .generic import GenericProvider

PROVIDER_REGISTRY = {
    "gmail": GmailProvider,
    "outlook": OutlookProvider,
    "generic": GenericProvider,
}


def create_provider(account):
    """Create a provider instance for the given account config."""
    provider_cls = PROVIDER_REGISTRY.get(account.provider)
    if not provider_cls:
        raise ValueError(f"Unknown provider: {account.provider}")
    return provider_cls(account)
