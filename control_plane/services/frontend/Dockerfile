# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy workspace root package files
COPY package.json package-lock.json* ./

# Copy shared-ui package
COPY packages/shared-ui/ packages/shared-ui/

# Copy frontend package files
COPY control_plane/services/frontend/package.json control_plane/services/frontend/

# Install dependencies (workspace-aware)
RUN npm ci --workspace=control_plane/services/frontend --workspace=packages/shared-ui --include-workspace-root

# Copy frontend source files
COPY control_plane/services/frontend/ control_plane/services/frontend/

# Build the application
RUN cd control_plane/services/frontend && npm run build

# Production stage
FROM nginx:alpine

# Copy built files from builder stage
COPY --from=builder /app/control_plane/services/frontend/dist /usr/share/nginx/html

# Copy nginx configuration
COPY control_plane/services/frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
