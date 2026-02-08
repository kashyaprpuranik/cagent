#!/bin/bash
# =============================================================================
# Data Plane Launcher
# =============================================================================
#
# Usage:
#   ./run.sh                    # Standard mode (runc)
#   ./run.sh --gvisor           # With gVisor isolation
#   ./run.sh --gvisor --ssh     # With gVisor + SSH access
#   ./run.sh --auditing         # With log forwarding to Loki
#   ./run.sh down               # Stop all services
#
# =============================================================================

set -e

PROFILES=""
ACTION="up -d"
export CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-runc}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --gvisor)
            # Check if gVisor is installed
            if ! command -v runsc &> /dev/null; then
                echo "Error: gVisor (runsc) is not installed."
                echo "Install from: https://gvisor.dev/docs/user_guide/install/"
                exit 1
            fi
            # Check if Docker is configured with runsc runtime
            if ! docker info 2>/dev/null | grep -q "runsc"; then
                echo "Error: Docker is not configured with gVisor runtime."
                echo "Run: sudo runsc install && sudo systemctl restart docker"
                exit 1
            fi
            export CONTAINER_RUNTIME=runsc
            echo "gVisor isolation enabled (runtime: runsc)"
            shift
            ;;
        --ssh)
            PROFILES="$PROFILES --profile ssh"
            echo "SSH access enabled"
            shift
            ;;
        --auditing)
            PROFILES="$PROFILES --profile auditing"
            echo "Auditing/logging enabled"
            shift
            ;;
        up|down|restart|logs|ps|build)
            ACTION="$1"
            shift
            break
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS] [ACTION] [ARGS...]"
            echo ""
            echo "Options:"
            echo "  --gvisor     Enable gVisor kernel isolation (requires runsc)"
            echo "  --ssh        Enable SSH access via FRP tunnel"
            echo "  --auditing   Enable log forwarding to Loki"
            echo ""
            echo "Actions:"
            echo "  up           Start services (default, detached)"
            echo "  down         Stop and remove services"
            echo "  restart      Restart services"
            echo "  logs         View logs (e.g., logs -f agent)"
            echo "  ps           List running services"
            echo "  build        Build images"
            echo ""
            echo "Examples:"
            echo "  $0                         # Start with runc (default)"
            echo "  $0 --gvisor                # Start with gVisor"
            echo "  $0 --gvisor --ssh          # Start with gVisor + SSH"
            echo "  $0 down                    # Stop all"
            echo "  $0 logs -f agent           # Follow agent logs"
            echo ""
            echo "Or set CONTAINER_RUNTIME=runsc in .env"
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# Handle action-specific behavior
case $ACTION in
    up)
        ACTION="up -d"
        ;;
esac

# Build and run
CMD="docker compose $PROFILES $ACTION $@"
echo "Runtime: $CONTAINER_RUNTIME"
echo "Running: $CMD"
exec $CMD
