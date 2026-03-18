"""Bearer token authentication for warden API.

Connected-mode DPs receive a WARDEN_API_TOKEN during provisioning.
The CP sends requests via mTLS with this token.

Localhost requests (SSH users on the host) bypass auth for convenience.
When WARDEN_API_TOKEN is empty (standalone mode), all requests are allowed.
"""

import runtime_config
from constants import WARDEN_API_TOKEN
from fastapi import HTTPException, Request, WebSocket

_LOCALHOST_PREFIXES = ("127.", "::1", "10.200.2.")


def _get_warden_token() -> str:
    """Get the current warden API token, checking runtime overrides first."""
    return runtime_config.get("WARDEN_API_TOKEN", WARDEN_API_TOKEN)


async def verify_warden_token(request: Request = None, websocket: WebSocket = None):
    """FastAPI dependency that verifies the warden bearer token.

    Works for both HTTP and WebSocket routes. FastAPI injects ``Request``
    for HTTP endpoints and ``WebSocket`` for WebSocket endpoints.

    Skips auth for:
    - Standard mode (no WARDEN_API_TOKEN set)
    - Localhost / infra-net requests (SSH user or Docker service)
    """
    token = _get_warden_token()
    if not token:
        return  # Standard mode — no auth required

    conn = request or websocket
    client_ip = conn.client.host if conn and conn.client else ""
    if any(client_ip.startswith(p) for p in _LOCALHOST_PREFIXES):
        return  # Local access — trusted

    # Check Authorization header (works for both HTTP and WebSocket upgrade)
    auth = conn.headers.get("Authorization", "") if conn else ""
    if not auth.startswith("Bearer ") or auth[7:] != token:
        raise HTTPException(status_code=401, detail="Invalid warden API token")
