# =============================================================================
# Warden - Unified data plane service
# Multi-stage build: Node (frontend) + Python (backend)
# =============================================================================

# Stage 1: Build frontend (only in admin profile)
FROM node:20-alpine AS frontend-builder

RUN apk add --no-cache git

WORKDIR /app

# Copy workspace root package files
COPY package.json package-lock.json* ./

# Copy frontend package files
COPY services/warden/frontend/package.json services/warden/frontend/

# Install dependencies (workspace-aware)
RUN npm ci --workspace=services/warden/frontend --include-workspace-root

# Copy frontend source
COPY services/warden/frontend/ services/warden/frontend/

# Build
RUN cd services/warden/frontend && npm run build

# Stage 2: Production image
FROM python:3.11-slim

WORKDIR /app

# Install wget for Docker health checks
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*

# Install uv for deterministic dependency installation
COPY --from=ghcr.io/astral-sh/uv:0.7 /uv /usr/local/bin/uv

# Install Python dependencies from lock file (supply chain protection:
# exclude-newer in pyproject.toml rejects packages uploaded after a cutoff date)
COPY services/warden/pyproject.toml services/warden/uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev && rm -rf /root/.cache
ENV PATH="/app/.venv/bin:$PATH"

# Copy warden code
COPY services/warden/ /app/

# Copy built frontend (may not exist in managed-only builds)
COPY --from=frontend-builder /app/services/warden/frontend/dist ./frontend/dist

ENV PYTHONUNBUFFERED=1

EXPOSE 8080 8443

CMD ["python", "main.py"]
