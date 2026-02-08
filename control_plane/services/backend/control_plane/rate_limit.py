from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from control_plane.config import REDIS_URL


def get_token_identifier(request: Request) -> str:
    """Rate limit by API token (not IP) for meaningful limiting."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        # Use first 16 chars of token as identifier (enough to be unique)
        return f"token:{auth[7:23]}"
    # Fall back to IP for unauthenticated requests
    return f"ip:{get_remote_address(request)}"


# Initialize limiter - use Redis if configured, otherwise in-memory
# In-memory is fine for single-instance deploys and tests
limiter = Limiter(
    key_func=get_token_identifier,
    storage_uri=REDIS_URL if REDIS_URL else "memory://",
    strategy="fixed-window",  # or "moving-window" for stricter limiting
)
