#!/bin/bash
# Run tests for the Cagent data plane.
#
# Usage:
#   ./scripts/test.sh              # DP unit/config + frontend type-check
#   ./scripts/test.sh --e2e        # All tests including DP e2e (legacy proxy)
#   ./scripts/test.sh --e2e --proxy-rust  # E2E with Rust proxy (cagent-proxy)
#   ./scripts/test.sh --e2e --no-teardown  # Keep containers running after e2e

set -e

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

RUN_E2E=false
NO_TEARDOWN=false
PROXY_MODE=legacy

for arg in "$@"; do
    case "$arg" in
        --e2e) RUN_E2E=true ;;
        --no-teardown) NO_TEARDOWN=true ;;
        --proxy-rust) PROXY_MODE=rust ;;
    esac
done

FAILED=()
declare -A TIMINGS

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ── DP Unit / Config Tests (isolated worktree) ────────────────────────────
# Run from a temporary git worktree so running containers (which modify
# configs/coredns/Corefile, configs/cagent.yaml, etc.) can't interfere.
echo "=== DP Unit / Config Tests ==="
echo ""
start=$SECONDS

UNIT_WORKTREE="/tmp/dp-unit-tests-$$"
git -C "$REPO_ROOT" worktree add --quiet "$UNIT_WORKTREE" HEAD 2>/dev/null
trap 'git -C "$REPO_ROOT" worktree remove --force "$UNIT_WORKTREE" 2>/dev/null || true' EXIT

cd "$UNIT_WORKTREE"
pip install -q -r requirements-test.txt
if pytest tests/ -v --ignore=tests/test_e2e.py; then
    echo ""
    echo -e "${GREEN}DP unit/config tests: PASSED${NC}"
else
    echo ""
    echo -e "${RED}DP unit/config tests: FAILED${NC}"
    FAILED+=("DP unit/config")
fi
TIMINGS["DP unit"]=$(( SECONDS - start ))
echo ""

# ── Frontend Type-Check (tsc) ─────────────────────────────────────────────
echo "=== Frontend Type-Check ==="
echo ""

echo "--- DP local admin UI (tsc) ---"
start=$SECONDS
# Install deps and type-check from the worktree (clean node_modules)
if (cd "$UNIT_WORKTREE" && npm install --workspaces --include-workspace-root --silent 2>/dev/null || true; cd services/warden/frontend && npx tsc --noEmit 2>&1); then
    echo -e "  ${GREEN}DP local admin frontend: OK${NC}"
else
    echo -e "  ${RED}DP local admin frontend: FAILED${NC}"
    FAILED+=("Frontend type-check")
fi
TIMINGS["DP frontend"]=$(( SECONDS - start ))
echo ""

# Clean up worktree before e2e (which uses the real repo)
git -C "$REPO_ROOT" worktree remove --force "$UNIT_WORKTREE" 2>/dev/null || true

# ── DP E2E Tests (standalone mode) ──────────────────────────────────────────
if [ "$RUN_E2E" = true ]; then
    echo "=== DP E2E Tests (standalone mode) ==="
    echo ""
    start=$SECONDS

    cd "$REPO_ROOT"
    CONTAINERS_STARTED=false

    # Isolate e2e from other compose stacks (local.sh, local_dp.sh)
    export COMPOSE_PROJECT_NAME=cagent-e2e
    export NET_OCTET=201
    export CP_PREFIX=e2e-
    export CELL_NET_NAME=cagent-e2e-cell-net
    export INFRA_NET_NAME=cagent-e2e-infra-net
    export SSH_PORT=3222
    export LOCAL_ADMIN_PORT=9081

    # E2E tests require: cell-dev (profile dev), warden (profile admin),
    # standalone mode. Bring up or restart as needed.
    NEED_RESTART=false

    # Check cell is running with the dev profile (runc), not standard (gVisor)
    CELL_CID=$(docker ps --filter "label=cagent.role=cell" --format "{{.ID}}" -q 2>/dev/null | head -1)
    if [ -n "$CELL_CID" ]; then
        CELL_SERVICE=$(docker inspect "$CELL_CID" --format '{{index .Config.Labels "com.docker.compose.service"}}' 2>/dev/null || true)
        if [ "$CELL_SERVICE" = "cell" ]; then
            echo "Cell is running with standard profile (gVisor), tearing down to restart with dev profile..."
            docker compose --profile standard --profile admin --profile email --profile auditing --profile proxy-rust down 2>/dev/null || true
            NEED_RESTART=true
        fi
    else
        NEED_RESTART=true
    fi

    # Check warden and log-shipper are running (admin profile)
    if [ "$NEED_RESTART" = false ]; then
        for svc in "${CP_PREFIX}warden" "${CP_PREFIX}log-shipper"; do
            if ! docker ps --filter "name=^${svc}$" --format "{{.Names}}" 2>/dev/null | grep -q "$svc"; then
                NEED_RESTART=true
                break
            fi
        done
    fi

    # Check warden is running in standalone mode
    if [ "$NEED_RESTART" = false ]; then
        ADMIN_MODE=$(curl -sf http://localhost:${LOCAL_ADMIN_PORT}/api/info 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('mode',''))" 2>/dev/null || true)
        if [ "$ADMIN_MODE" = "connected" ]; then
            echo "Data plane is running in connected mode, restarting in standalone mode..."
            docker compose --profile dev --profile admin --profile email --profile auditing --profile proxy-rust --profile proxy-legacy down 2>/dev/null || true
            NEED_RESTART=true
        fi
    fi

    # Generate certs (MITM CA + mTLS)
    bash "$REPO_ROOT/scripts/setup.sh"
    export PROXY_MODE="$PROXY_MODE"

    # Cell-side proxy env vars depend on the proxy mode.  These control
    # docker-compose's CELL_* variables for the cell containers; they are
    # NOT the script's HTTPS_PROXY (that's set after build below to avoid
    # poisoning image pulls with the not-yet-running mitmproxy address).
    if [ "$PROXY_MODE" = "rust" ]; then
        export CELL_HTTP_PROXY="http://10.${NET_OCTET}.1.20:18443"
        export CELL_HTTPS_PROXY="http://10.${NET_OCTET}.1.20:18443"
        export CELL_DNS_PRIMARY="10.${NET_OCTET}.1.20"
        export CELL_DNS_SECONDARY="10.${NET_OCTET}.1.20"
        export CAGENT_PROXY_URL="http://10.${NET_OCTET}.2.20:18080"
        export DEVBOX_LOCAL_IP="10.${NET_OCTET}.1.20"
        # Exercise the authenticated config push path end-to-end.
        # Must be set identically on warden and cagent-proxy (wired via
        # docker-compose.yml).
        export CAGENT_PROXY_TOKEN="${CAGENT_PROXY_TOKEN:-e2e-test-token}"
    else
        export CELL_HTTPS_PROXY="http://10.${NET_OCTET}.1.15:8080"
    fi
    export WARDEN_TLS_CERT="$(base64 -w0 "$REPO_ROOT/configs/mtls/server-cert.pem")"
    export WARDEN_TLS_KEY="$(base64 -w0 "$REPO_ROOT/configs/mtls/server-key.pem")"
    export WARDEN_MTLS_CA_CERT="$(base64 -w0 "$REPO_ROOT/configs/mtls/ca-cert.pem")"
    export WARDEN_MTLS_PORT=9444

    # Snapshot tracked config files that containers modify at runtime
    cp configs/cagent.yaml configs/.cagent.yaml.bak
    cp configs/coredns/Corefile configs/coredns/.Corefile.bak

    # Use a temp path for runtime config so e2e never reads/writes the repo checkout
    export RUNTIME_CONFIG_PATH=/tmp/runtime_config.json

    if [ "$NEED_RESTART" = true ]; then
        echo "Stopping any existing containers first..."
        # Use -v to remove volumes (proxy-config may have stale envoy config from
        # a prior connected-mode run, e.g. CP+DP e2e) and --remove-orphans to catch
        # containers started with a different compose file (e.g. e2e override).
        docker compose --profile dev --profile admin --profile managed --profile email --profile auditing --profile proxy-rust --profile proxy-legacy down -v --remove-orphans 2>/dev/null || true
        docker compose --profile standard --profile admin --profile managed --profile email --profile auditing --profile proxy-rust --profile proxy-legacy down -v --remove-orphans 2>/dev/null || true

        # Clean up stale networks (may have wrong labels or orphan endpoints)
        for net in "$INFRA_NET_NAME" "$CELL_NET_NAME"; do
            if docker network inspect "$net" >/dev/null 2>&1; then
                for cid in $(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null); do
                    echo "  Removing orphan container $cid from $net..."
                    docker stop "$cid" 2>/dev/null || true
                    docker rm "$cid" 2>/dev/null || true
                done
                docker network rm "$net" 2>/dev/null || true
            fi
        done

        # Also clean up e2e-bridge network left by CP+DP e2e
        docker network rm e2e-bridge 2>/dev/null || true

        E2E_PROFILES="--profile dev --profile admin --profile auditing"
        if [ "$PROXY_MODE" = "rust" ]; then
            E2E_PROFILES="$E2E_PROFILES --profile proxy-rust"
        else
            E2E_PROFILES="$E2E_PROFILES --profile proxy-legacy"
        fi
        echo "Starting data plane (standalone, $E2E_PROFILES, proxy=$PROXY_MODE, 2 cells)..."
        DATAPLANE_MODE=standalone docker compose $E2E_PROFILES up -d --build --remove-orphans --scale cell-dev=2
        CONTAINERS_STARTED=true
        echo "Waiting for containers to stabilize..."
        sleep 10
    else
        E2E_PROFILES="--profile dev --profile admin --profile auditing"
        if [ "$PROXY_MODE" = "rust" ]; then
            E2E_PROFILES="$E2E_PROFILES --profile proxy-rust"
        else
            E2E_PROFILES="$E2E_PROFILES --profile proxy-legacy"
        fi
        echo "Data plane already running, rebuilding images in case code changed..."
        DATAPLANE_MODE=standalone docker compose $E2E_PROFILES up -d --build --scale cell-dev=2
        echo "Waiting for containers to stabilize..."
        sleep 5
    fi

    # Export HTTPS_PROXY *after* build — it's for cell containers, not Docker
    # builds.  Point at the proxy that's actually running for this mode.
    if [ "$PROXY_MODE" = "rust" ]; then
        export HTTPS_PROXY="http://10.${NET_OCTET}.1.20:18443"
    else
        export HTTPS_PROXY="http://10.${NET_OCTET}.1.15:8080"
    fi

    set +e
    pytest tests/test_e2e.py -v
    E2E_EXIT=$?
    set -e

    # Tear down containers only if we started them (unless --no-teardown)
    if [ "$CONTAINERS_STARTED" = true ] && [ "$NO_TEARDOWN" = false ]; then
        echo ""
        echo "Stopping containers started by this script..."
        docker compose --profile dev --profile admin --profile email --profile auditing --profile proxy-rust --profile proxy-legacy down 2>/dev/null || true
    elif [ "$NO_TEARDOWN" = true ]; then
        echo ""
        echo "Keeping containers running (--no-teardown)"
    fi

    # Restore tracked config files modified by containers at runtime
    mv configs/.cagent.yaml.bak configs/cagent.yaml 2>/dev/null || true
    mv configs/coredns/.Corefile.bak configs/coredns/Corefile 2>/dev/null || true

    if [ $E2E_EXIT -ne 0 ]; then
        FAILED+=("DP e2e")
    else
        echo ""
        echo -e "${GREEN}DP e2e tests: PASSED${NC}"
    fi
    TIMINGS["DP e2e"]=$(( SECONDS - start ))
    echo ""
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo "==========================================="
if [ ${#FAILED[@]} -eq 0 ]; then
    echo -e "${GREEN}All DP test suites passed.${NC}"
else
    echo -e "${RED}FAILED suites: ${FAILED[*]}${NC}"
fi
echo ""
echo "Timings:"
for suite in "DP unit" "DP frontend" "DP e2e"; do
    if [ -n "${TIMINGS[$suite]+x}" ]; then
        elapsed=${TIMINGS[$suite]}
        printf "  %-20s %dm%02ds\n" "$suite" $(( elapsed / 60 )) $(( elapsed % 60 ))
    fi
done
echo "==========================================="

if [ ${#FAILED[@]} -gt 0 ]; then
    exit 1
fi
