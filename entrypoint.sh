#!/bin/bash
set -e

# =============================================================================
# Data Plane Entrypoint
# Starts Docker daemon and infrastructure services, then runs user command
# =============================================================================

echo "Starting Docker daemon..."
dockerd &

# Wait for Docker to be ready
echo "Waiting for Docker..."
timeout=30
while ! docker info >/dev/null 2>&1; do
    sleep 1
    timeout=$((timeout - 1))
    if [ $timeout -le 0 ]; then
        echo "ERROR: Docker failed to start"
        exit 1
    fi
done
echo "Docker is ready"

# Start infrastructure services
echo "Starting infrastructure services..."
cd /opt/infrastructure
docker compose up -d

echo "Infrastructure services started:"
docker compose ps

# Switch to workspace
cd /workspace

# Configure DNS to use our filtered DNS
echo "nameserver 10.200.1.5" > /etc/resolv.conf

# Set proxy environment for the user
export HTTP_PROXY=http://10.200.1.10:8443
export HTTPS_PROXY=http://10.200.1.10:8443
export NO_PROXY=localhost,127.0.0.1,10.200.1.0/24

# Write proxy config for aiuser
cat >> /home/aiuser/.bashrc << 'EOF'
export HTTP_PROXY=http://10.200.1.10:8443
export HTTPS_PROXY=http://10.200.1.10:8443
export NO_PROXY=localhost,127.0.0.1,10.200.1.0/24
EOF

if [ -n "$CONTROL_PLANE_HOST" ]; then
    echo ""
    echo "Control plane: $CONTROL_PLANE_HOST"
    echo "  - API:     http://$CONTROL_PLANE_HOST:8002"
    echo "  - Grafana: http://$CONTROL_PLANE_HOST:3000"
fi

echo ""
echo "=== AI Devbox Ready ==="
echo "Workspace: /workspace"
echo "Egress:    All traffic proxied through Envoy"
echo "DNS:       Filtered (allowlist only)"
echo ""

# Run the user's command (default: /bin/bash)
exec gosu aiuser "$@"
