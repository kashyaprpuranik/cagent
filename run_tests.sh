#!/bin/bash
# Run all tests across the Cagent project.
#
# Usage:
#   ./run_tests.sh                # CP + DP unit/config tests only
#   ./run_tests.sh --e2e          # all tests including DP e2e and CP+DP e2e
#   ./run_tests.sh --cp           # CP backend tests only
#   ./run_tests.sh --dp           # DP unit/config tests only
#   ./run_tests.sh --dp-e2e       # DP e2e tests only
#   ./run_tests.sh --cp-dp-e2e    # CP+DP integration e2e tests only

set -e

REPO_ROOT=$(cd "$(dirname "$0")" && pwd)

RUN_CP=false
RUN_DP=false
RUN_DP_E2E=false
RUN_CP_DP_E2E=false
EXPLICIT=false

for arg in "$@"; do
    case "$arg" in
        --cp)         RUN_CP=true; EXPLICIT=true ;;
        --dp)         RUN_DP=true; EXPLICIT=true ;;
        --dp-e2e)     RUN_DP_E2E=true; EXPLICIT=true ;;
        --cp-dp-e2e)  RUN_CP_DP_E2E=true; EXPLICIT=true ;;
        --e2e)        RUN_CP=true; RUN_DP=true; RUN_DP_E2E=true; RUN_CP_DP_E2E=true; EXPLICIT=true ;;
    esac
done

# Default: CP + DP unit/config tests (no e2e)
if [ "$EXPLICIT" = false ]; then
    RUN_CP=true
    RUN_DP=true
fi

FAILED=()

# ── CP Backend Tests ────────────────────────────────────────────────────────
if [ "$RUN_CP" = true ]; then
    echo "=== CP Backend Tests ==="
    echo ""
    if bash "$REPO_ROOT/control_plane/services/backend/run_tests.sh"; then
        echo ""
        echo "CP backend tests: PASSED"
    else
        echo ""
        echo "CP backend tests: FAILED"
        FAILED+=("CP backend")
    fi
    echo ""
fi

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

# ── CP+DP Integration E2E Tests (connected mode) ───────────────────────────
if [ "$RUN_CP_DP_E2E" = true ]; then
    echo "=== CP+DP Integration E2E Tests (connected mode) ==="
    echo ""
    if bash "$REPO_ROOT/e2e/run_tests.sh"; then
        echo ""
        echo "CP+DP e2e tests: PASSED"
    else
        echo ""
        echo "CP+DP e2e tests: FAILED"
        FAILED+=("CP+DP e2e")
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
