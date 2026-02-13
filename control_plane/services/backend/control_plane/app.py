import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from control_plane.lifespan import lifespan
from control_plane.rate_limit import limiter

logger = logging.getLogger(__name__)

from control_plane.config import CORS_ORIGINS, BETA_FEATURES
from control_plane.database import Base, engine
from control_plane.models import (  # noqa: F401 - ensure models are registered
    Tenant, TenantIpAcl, AuditTrail, DomainPolicy, EmailPolicy,
    SecurityProfile, AgentState, TerminalSession, ApiToken, WebSocketTicket,
)
from control_plane.routes import health, logs, domain_policies, email_policies, agents, terminal, tenants, ip_acls, tokens, analytics, security_profiles

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Devbox Control Plane",
    description="Management API for Secure AI Devbox",
    version="1.0.0",
    lifespan=lifespan,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Register rate limiter with app
app.state.limiter = limiter


def _log_rate_limit_exceeded(request, exc):
    logger.warning(
        "Rate limit exceeded: %s %s (key=%s, limit=%s)",
        request.method, request.url.path,
        getattr(exc, "detail", ""),
        str(exc),
    )
    return JSONResponse(
        status_code=429,
        content={"error": f"Rate limit exceeded: {exc.detail}"},
    )

app.add_exception_handler(RateLimitExceeded, _log_rate_limit_exceeded)

if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Include routers
app.include_router(health.router)
app.include_router(logs.router)
app.include_router(domain_policies.router)
if "email" in BETA_FEATURES:
    app.include_router(email_policies.router)
app.include_router(security_profiles.router)
app.include_router(agents.router)
app.include_router(terminal.router)
app.include_router(tenants.router)
app.include_router(ip_acls.router)
app.include_router(tokens.router)
app.include_router(analytics.router)
