#!/bin/bash
# Run tests for the Cagent data plane.
#
# Usage:
#   ./run_tests.sh                # DP unit/config + frontend type-check
#   ./run_tests.sh --e2e          # All tests including DP e2e
#   ./run_tests.sh --dp           # DP unit/config tests only
#   ./run_tests.sh --frontend     # Frontend type-check only (tsc)
#   ./run_tests.sh --dp-e2e       # DP e2e tests only

set -e

REPO_ROOT=$(cd "$(dirname "$0")" && pwd)

RUN_DP=false
RUN_FRONTEND=false
RUN_DP_E2E=false
EXPLICIT=false

for arg in "$@"; do
    case "$arg" in
        --dp)         RUN_DP=true; EXPLICIT=true ;;
        --frontend)   RUN_FRONTEND=true; EXPLICIT=true ;;
        --dp-e2e)     RUN_DP_E2E=true; EXPLICIT=true ;;
        --e2e)        RUN_DP=true; RUN_FRONTEND=true; RUN_DP_E2E=true; EXPLICIT=true ;;
    esac
done

# Default: DP unit/config tests + frontend type-check (no e2e)
if [ "$EXPLICIT" = false ]; then
    RUN_DP=true
    RUN_FRONTEND=true
fi

FAILED=()

# ── DP Unit / Config Tests ──────────────────────────────────────────────────
if [ "$RUN_DP" = true ]; then
    echo "=== DP Unit / Config Tests ==="
    echo ""
    if bash "$REPO_ROOT/data_plane/run_tests.sh"; then
        echo ""
        echo "DP unit/config tests: PASSED"
    else
        echo ""
        echo "DP unit/config tests: FAILED"
        FAILED+=("DP unit/config")
    fi
    echo ""
fi

# ── Frontend Type-Check (tsc) ─────────────────────────────────────────────
if [ "$RUN_FRONTEND" = true ]; then
    echo "=== Frontend Type-Check ==="
    echo ""

    # Ensure dependencies are installed
    cd "$REPO_ROOT"
    npm install --workspaces --include-workspace-root --silent 2>/dev/null || true

    echo "--- DP local admin UI (tsc) ---"
    if (cd "$REPO_ROOT/data_plane/services/local_admin/frontend" && npx tsc --noEmit 2>&1); then
        echo "  DP local admin frontend: OK"
    else
        echo "  DP local admin frontend: FAILED"
        FAILED+=("Frontend type-check")
    fi
    echo ""
fi

# ── DP E2E Tests (standalone mode) ──────────────────────────────────────────
if [ "$RUN_DP_E2E" = true ]; then
    echo "=== DP E2E Tests (standalone mode) ==="
    echo ""
    if bash "$REPO_ROOT/data_plane/run_tests.sh" --e2e-only; then
        echo ""
        echo "DP e2e tests: PASSED"
    else
        echo ""
        echo "DP e2e tests: FAILED"
        FAILED+=("DP e2e")
    fi
    echo ""
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo "==========================================="
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "All test suites passed."
else
    echo "FAILED suites: ${FAILED[*]}"
    exit 1
fi
