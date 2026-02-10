# =============================================================================
# Local Admin - Standalone data plane management UI
# Multi-stage build: Node (frontend) + Python (backend)
# =============================================================================

# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app

# Copy workspace root package files
COPY package.json package-lock.json* ./

# Copy shared-ui package
COPY packages/shared-ui/ packages/shared-ui/

# Copy frontend package files
COPY data_plane/services/local_admin/frontend/package.json data_plane/services/local_admin/frontend/

# Install dependencies (workspace-aware)
RUN npm ci --workspace=data_plane/services/local_admin/frontend --workspace=packages/shared-ui --include-workspace-root

# Copy frontend source
COPY data_plane/services/local_admin/frontend/ data_plane/services/local_admin/frontend/

# Build
RUN cd data_plane/services/local_admin/frontend && npm run build

# Stage 2: Production image
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY data_plane/services/local_admin/backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend
COPY data_plane/services/local_admin/backend/ ./backend/

# Copy built frontend
COPY --from=frontend-builder /app/data_plane/services/local_admin/frontend/dist ./frontend/dist

# Create non-root user with docker group access
ARG DOCKER_GID=124
RUN groupadd -g ${DOCKER_GID} docker || true && \
    useradd -m -u 1000 -G ${DOCKER_GID} appuser
USER appuser

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
