"""Bearer token authentication for warden API.

Interactive-mode DPs receive a WARDEN_API_TOKEN during provisioning.
The CP proxies requests via Cloudflare Tunnel with this token.

Localhost requests (SSH users on the host) bypass auth for convenience.
When WARDEN_API_TOKEN is empty (standard mode), all requests are allowed.
"""

from constants import WARDEN_API_TOKEN
from fastapi import HTTPException, Request, WebSocket

_LOCALHOST_PREFIXES = ("127.", "::1", "10.200.2.")


async def verify_warden_token(request: Request = None, websocket: WebSocket = None):
    """FastAPI dependency that verifies the warden bearer token.

    Works for both HTTP and WebSocket routes. FastAPI injects ``Request``
    for HTTP endpoints and ``WebSocket`` for WebSocket endpoints.

    Skips auth for:
    - Standard mode (no WARDEN_API_TOKEN set)
    - Localhost / infra-net requests (SSH user or Docker service)
    """
    if not WARDEN_API_TOKEN:
        return  # Standard mode — no auth required

    conn = request or websocket
    client_ip = conn.client.host if conn and conn.client else ""
    if any(client_ip.startswith(p) for p in _LOCALHOST_PREFIXES):
        return  # Local access — trusted

    # Check Authorization header (works for both HTTP and WebSocket upgrade)
    auth = conn.headers.get("Authorization", "") if conn else ""
    if not auth.startswith("Bearer ") or auth[7:] != WARDEN_API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid warden API token")
