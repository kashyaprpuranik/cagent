#!/bin/bash
# =============================================================================
# STCP SSH Tunnel Setup Script
# =============================================================================
#
# Sets up SSH tunnel access to the agent container via STCP.
# This script:
#   1. Generates STCP secret via control plane API
#   2. Updates .env with tunnel configuration
#   3. Restarts the frpc container
#
# Usage:
#   ./setup-ssh-tunnel.sh [OPTIONS]
#
# Options:
#   --control-plane URL    Control plane URL (default: from .env or localhost:8002)
#   --token TOKEN          Admin token (default: from .env)
#   --agent-id ID          Agent ID (default: from .env or "default")
#   --frp-server HOST      FRP server address (default: control plane host)
#   --frp-port PORT        FRP server port (default: 7000)
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Change to data-plane directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_PLANE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DATA_PLANE_DIR"

# Load existing .env if present
if [[ -f .env ]]; then
    source .env 2>/dev/null || true
fi

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --control-plane)
            CONTROL_PLANE_URL="$2"
            shift 2
            ;;
        --token)
            CONTROL_PLANE_TOKEN="$2"
            shift 2
            ;;
        --agent-id)
            AGENT_ID="$2"
            shift 2
            ;;
        --frp-server)
            FRP_SERVER_ADDR="$2"
            shift 2
            ;;
        --frp-port)
            FRP_SERVER_PORT="$2"
            shift 2
            ;;
        --help|-h)
            head -30 "$0" | tail -25
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Defaults
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://localhost:8002}"
AGENT_ID="${AGENT_ID:-default}"
FRP_SERVER_PORT="${FRP_SERVER_PORT:-7000}"

# Extract host from control plane URL for FRP server default
if [[ -z "$FRP_SERVER_ADDR" ]]; then
    FRP_SERVER_ADDR=$(echo "$CONTROL_PLANE_URL" | sed -E 's|https?://||' | cut -d: -f1)
fi

# Validate required settings
if [[ -z "$CONTROL_PLANE_TOKEN" ]]; then
    log_error "CONTROL_PLANE_TOKEN is required. Set in .env or pass --token"
    exit 1
fi

echo ""
log_info "STCP SSH Tunnel Setup"
echo "======================================"
echo "Control Plane: $CONTROL_PLANE_URL"
echo "Agent ID:      $AGENT_ID"
echo "FRP Server:    $FRP_SERVER_ADDR:$FRP_SERVER_PORT"
echo ""

# =============================================================================
# Step 1: Generate STCP secret
# =============================================================================

log_step "Generating STCP secret via control plane API..."

RESPONSE=$(curl -s -X POST \
    "${CONTROL_PLANE_URL}/api/v1/agents/${AGENT_ID}/stcp-secret" \
    -H "Authorization: Bearer ${CONTROL_PLANE_TOKEN}" \
    -H "Content-Type: application/json" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" != "200" ]]; then
    log_error "Failed to generate STCP secret (HTTP $HTTP_CODE)"
    echo "$BODY"
    exit 1
fi

STCP_SECRET_KEY=$(echo "$BODY" | grep -o '"stcp_secret_key"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)

if [[ -z "$STCP_SECRET_KEY" ]]; then
    log_error "Failed to parse STCP secret from response"
    echo "$BODY"
    exit 1
fi

log_info "Generated STCP secret: ${STCP_SECRET_KEY:0:8}..."

# =============================================================================
# Step 2: Update .env file
# =============================================================================

log_step "Updating .env file..."

# Create .env if it doesn't exist
touch .env

# Function to update or add env var
update_env() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        echo "${key}=${value}" >> .env
    fi
}

update_env "CONTROL_PLANE_URL" "$CONTROL_PLANE_URL"
update_env "CONTROL_PLANE_TOKEN" "$CONTROL_PLANE_TOKEN"
update_env "AGENT_ID" "$AGENT_ID"
update_env "FRP_SERVER_ADDR" "$FRP_SERVER_ADDR"
update_env "FRP_SERVER_PORT" "$FRP_SERVER_PORT"
update_env "STCP_SECRET_KEY" "$STCP_SECRET_KEY"

log_info "Updated .env with tunnel configuration"

# =============================================================================
# Step 3: Restart frpc container
# =============================================================================

log_step "Starting SSH tunnel (frpc container)..."

# Check if docker-compose or docker compose is available
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    log_error "Neither docker-compose nor docker compose found"
    exit 1
fi

# Stop existing frpc if running
$COMPOSE_CMD --profile ssh stop frpc 2>/dev/null || true

# Start frpc
$COMPOSE_CMD --profile ssh up -d frpc

log_info "SSH tunnel started"

# =============================================================================
# Step 4: Generate visitor config
# =============================================================================

log_step "Generating visitor configuration..."

VISITOR_CONFIG="configs/frpc/frpc-visitor.toml"

cat > "$VISITOR_CONFIG" << EOF
# STCP Visitor Configuration
# Run this on your local machine to connect to the agent
#
# Usage:
#   frpc -c frpc-visitor.toml
#   ssh -p 2222 agent@127.0.0.1

serverAddr = "${FRP_SERVER_ADDR}"
serverPort = ${FRP_SERVER_PORT}

[[visitors]]
name = "${AGENT_ID}-ssh-visitor"
type = "stcp"
serverName = "${AGENT_ID}-ssh"
secretKey = "${STCP_SECRET_KEY}"
bindAddr = "127.0.0.1"
bindPort = 2222
EOF

log_info "Created visitor config: $VISITOR_CONFIG"

# =============================================================================
# Done
# =============================================================================

echo ""
echo "======================================"
log_info "SSH tunnel setup complete!"
echo ""
echo "To connect from your local machine:"
echo ""
echo "  1. Copy the visitor config to your machine:"
echo "     scp ${DATA_PLANE_DIR}/${VISITOR_CONFIG} ~/frpc-visitor.toml"
echo ""
echo "  2. Run frpc with the visitor config:"
echo "     frpc -c ~/frpc-visitor.toml"
echo ""
echo "  3. SSH to the agent:"
echo "     ssh -p 2222 agent@127.0.0.1"
echo ""
