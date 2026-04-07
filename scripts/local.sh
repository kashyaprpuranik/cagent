#!/bin/bash
# =============================================================================
# Cagent Data Plane - Development Environment
# =============================================================================
#
# Starts the data plane in standalone mode for local development.
#
# Usage:
#   ./scripts/local.sh                     # Standalone with admin UI (default)
#   ./scripts/local.sh --minimal           # Minimal (no warden, static config)
#   ./scripts/local.sh --gvisor            # Use gVisor runtime
#   ./scripts/local.sh --beta              # Enable beta features (email proxy)
#   ./scripts/local.sh --no-mtls           # Disable warden mTLS listener
#   ./scripts/local.sh down                # Stop everything
#
# For full stack (CP + DP), use the cagent-control repo:
#   cd ../cagent-control && ./dev_up.sh
#
# External callers (e.g. cagent-control/scripts/local.sh) can pre-set env vars
# (DATAPLANE_MODE, DP_PROFILES, COMPOSE_PROJECT_NAME, SCALE_FLAG, MTLS) to
# override defaults without passing CLI flags.
#
# NOT for production use.
# =============================================================================

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Defaults (respect pre-set env vars for external callers like cagent-control)
DP_PROFILES="${DP_PROFILES:-"--profile admin"}"
DP_AGENT_PROFILE="${DP_AGENT_PROFILE:-dev}"
ACTION="${ACTION:-up}"
MINIMAL="${MINIMAL:-false}"
MTLS="${MTLS:-true}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal)
            MINIMAL=true
            DP_PROFILES=""
            shift
            ;;
        --gvisor)
            if ! command -v runsc &> /dev/null; then
                echo "Error: gVisor (runsc) is not installed."
                exit 1
            fi
            DP_AGENT_PROFILE="standard"
            shift
            ;;
        --beta)
            export BETA_FEATURES="email"
            DP_PROFILES="$DP_PROFILES --profile email"
            shift
            ;;
        --no-mtls)
            MTLS=false
            shift
            ;;
        down)
            ACTION="down"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS] [ACTION]"
            echo ""
            echo "Options:"
            echo "  --minimal       Minimal mode (no warden, static config)"
            echo "  --gvisor        Use gVisor runtime (default: runc)"
            echo "  --beta          Enable beta features (email proxy)"
            echo "  --no-mtls       Disable warden mTLS listener (enabled by default)"
            echo ""
            echo "Actions:"
            echo "  down            Stop all services"
            echo ""
            echo "Examples:"
            echo "  $0                        # Standalone with admin UI"
            echo "  $0 --minimal              # Minimal (3 containers only)"
            echo "  $0 --gvisor               # With gVisor runtime"
            echo "  $0 down                   # Stop everything"
            echo ""
            echo "For full stack (CP + DP), use the cagent-control repo:"
            echo "  cd ../cagent-control && ./dev_up.sh"
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (use --help for usage)"
            exit 1
            ;;
    esac
done

# =============================================================================
# Main
# =============================================================================

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cagent-local}"
# NET_OCTET=200 (default), no CP_PREFIX, no network name overrides needed

echo "=== Cagent Data Plane Development Environment ==="
echo "Directory: $ROOT_DIR"

cd "$ROOT_DIR"

# --- Handle 'down' action ---
if [ "$ACTION" = "down" ]; then
    echo "Stopping Data Plane..."
    docker compose --profile dev --profile standard --profile admin --profile managed --profile auditing --profile email down --remove-orphans 2>/dev/null || true
    echo ""
    echo "=== All services stopped ==="
    exit 0
fi

# --- Cert generation (MITM CA + mTLS) ---
bash "$ROOT_DIR/scripts/setup.sh"

if [ "${MTLS:-false}" = true ] && [ -z "${WARDEN_TLS_CERT:-}" ]; then
    export WARDEN_TLS_CERT="$(base64 -w0 "$ROOT_DIR/configs/mtls/server-cert.pem")"
    export WARDEN_TLS_KEY="$(base64 -w0 "$ROOT_DIR/configs/mtls/server-key.pem")"
    export WARDEN_MTLS_CA_CERT="$(base64 -w0 "$ROOT_DIR/configs/mtls/ca-cert.pem")"
    echo "mTLS enabled (warden will listen on port 8443)"
fi

# --- Start services ---
export DATAPLANE_MODE="${DATAPLANE_MODE:-standalone}"

profiles="--profile $DP_AGENT_PROFILE $DP_PROFILES"

echo "Building images..."
docker compose $profiles build

# Export HTTPS_PROXY *after* build — it's intended for cell containers, not
# the build process. Exporting before build causes image pulls to route
# through the mitmproxy container that hasn't been started yet.
if [ "$MINIMAL" = false ]; then
    export HTTPS_PROXY="http://10.${NET_OCTET:-200}.1.15:8080"
    echo "MITM proxy enabled (HTTPS via mitmproxy -> Envoy)"
fi

echo "Starting services..."
docker compose $profiles up -d ${SCALE_FLAG:-}

# Wait for cell container(s)
echo "Waiting for cell container(s)..."
RETRIES=20
until docker ps --filter "label=cagent.role=cell" -q 2>/dev/null | grep -q .; do
    RETRIES=$((RETRIES - 1))
    if [ $RETRIES -le 0 ]; then
        echo "  ERROR: Cell container(s) failed to start"
        docker compose $profiles logs 2>/dev/null | tail -20
        exit 1
    fi
    sleep 2
done
echo "  Cell container(s): OK"

# Wait for HTTP proxy
echo "Waiting for HTTP proxy..."
CELL_CONTAINER=$(docker ps --filter "label=cagent.role=cell" --format "{{.Names}}" | head -1)
RETRIES=15
until docker exec "$CELL_CONTAINER" curl -sf -x http://10.${NET_OCTET:-200}.1.10:8443 --connect-timeout 2 http://api.github.com/ -o /dev/null 2>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if [ $RETRIES -le 0 ]; then
        echo "  WARNING: HTTP proxy health check timed out (continuing anyway)"
        break
    fi
    sleep 2
done
echo "  HTTP proxy: OK"

# Wait for MITM proxy
if [ "$MINIMAL" = false ]; then
    echo "Waiting for MITM proxy..."
    RETRIES=15
    until docker exec "$CELL_CONTAINER" curl -sf -x http://10.${NET_OCTET:-200}.1.15:8080 --connect-timeout 2 https://api.github.com/ -o /dev/null 2>/dev/null; do
        RETRIES=$((RETRIES - 1))
        if [ $RETRIES -le 0 ]; then
            echo "  WARNING: MITM proxy health check timed out (continuing anyway)"
            break
        fi
        sleep 2
    done
    echo "  MITM proxy: OK"
fi

echo ""
echo "=== Data Plane ready ($DATAPLANE_MODE) ==="
echo ""
echo "Cell container: docker exec -it $CELL_CONTAINER bash"
if echo "$DP_PROFILES" | grep -q "admin"; then
    echo "Admin UI: http://localhost:${LOCAL_ADMIN_PORT:-8081}"
fi
if [ "${MTLS:-false}" = true ]; then
    echo "mTLS test: curl --cert configs/mtls/client-cert.pem --key configs/mtls/client-key.pem --cacert configs/mtls/ca-cert.pem https://localhost:8443/api/health"
fi
