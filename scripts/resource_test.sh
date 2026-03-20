#!/bin/bash
# =============================================================================
# Resource Limit Testing for DP Infrastructure Containers
# =============================================================================
#
# Binary-searches for the minimum resource limits that allow all infra
# containers to start and pass a full health check, maximizing what's
# left for the cell container on a fixed-size server (e.g., 2 vCPU / 4GB).
#
# How it works:
#   1. Generates a docker-compose override file with trial resource limits
#   2. Starts the full DP stack (cell + all infra)
#   3. Runs a health check: DNS, HTTP proxy, HTTPS/MITM proxy, warden API,
#      OpenObserve API, and 30s stability (no OOM kills or restarts)
#   4. Records PASS/FAIL and tears down
#   5. Repeats with progressively lower limits
#
# Usage:
#   ./scripts/resource_test.sh                  # Run default trials
#   COMPOSE_DIR=/path/to/cagent ./scripts/...   # Override repo path
#   PROFILES="--profile dev ..." ./scripts/...  # Override profiles
#
# Output:
#   Results are printed to stdout and logged to /tmp/dp-resource-results.txt
#
# After running, update docker-compose.yml resource limits to the lowest
# passing trial (with a safety margin). Document the chosen values in the
# Resource Budget comment block at the top of docker-compose.yml.
#
# Last run: 2026-03-20, 19 trials, floor at 0.40 CPU / 336M infra
# =============================================================================

set -euo pipefail

COMPOSE_DIR="${COMPOSE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
PROFILES="${PROFILES:---profile dev --profile auditing --profile managed}"
OVERRIDE="/tmp/dp-resource-override.yml"
RESULTS="/tmp/dp-resource-results.txt"

echo "=== DP Resource Minimization Test ===" | tee "$RESULTS"
echo "Started: $(date)" | tee -a "$RESULTS"
echo "Compose dir: $COMPOSE_DIR" | tee -a "$RESULTS"
echo "Profiles: $PROFILES" | tee -a "$RESULTS"
echo "" | tee -a "$RESULTS"

# --- Override file generator ---

write_override() {
    local envoy_cpu=$1 envoy_mem=$2
    local mitm_cpu=$3 mitm_mem=$4
    local vector_cpu=$5 vector_mem=$6
    local warden_cpu=$7 warden_mem=$8
    local ozo_cpu=$9 ozo_mem=${10}
    local dns_mem=${11}
    local cell_cpu=${12} cell_mem=${13}

    # Detect cell service name from profiles
    local cell_svc="cell-dev"
    if echo "$PROFILES" | grep -q "standard"; then
        cell_svc="cell"
    fi

    cat > "$OVERRIDE" <<YAML
services:
  http-proxy:
    deploy:
      resources:
        limits:
          cpus: '${envoy_cpu}'
          memory: ${envoy_mem}M
        reservations:
          cpus: '0.05'
          memory: 32M
  mitm-proxy:
    deploy:
      resources:
        limits:
          cpus: '${mitm_cpu}'
          memory: ${mitm_mem}M
        reservations:
          cpus: '0.05'
          memory: 32M
  log-shipper:
    deploy:
      resources:
        limits:
          cpus: '${vector_cpu}'
          memory: ${vector_mem}M
        reservations:
          cpus: '0.05'
          memory: 32M
  warden:
    deploy:
      resources:
        limits:
          cpus: '${warden_cpu}'
          memory: ${warden_mem}M
        reservations:
          cpus: '0.05'
          memory: 32M
  log-store:
    deploy:
      resources:
        limits:
          cpus: '${ozo_cpu}'
          memory: ${ozo_mem}M
        reservations:
          cpus: '0.05'
          memory: 32M
  dns-filter:
    deploy:
      resources:
        limits:
          cpus: '0.05'
          memory: ${dns_mem}M
        reservations:
          cpus: '0.05'
          memory: 16M
  ${cell_svc}:
    deploy:
      resources:
        limits:
          cpus: '${cell_cpu}'
          memory: ${cell_mem}M
        reservations:
          cpus: '0.1'
          memory: 128M
YAML
}

# --- Compose wrapper (remap warden mTLS port to avoid conflicts) ---

compose() {
    WARDEN_MTLS_PORT="${WARDEN_MTLS_PORT:-18443}" \
        docker compose -f "$COMPOSE_DIR/docker-compose.yml" -f "$OVERRIDE" $PROFILES "$@"
}

teardown() {
    compose down --remove-orphans --timeout 10 2>/dev/null || true
}

# --- Health check ---

verify() {
    local label=$1
    echo "--- Verifying: $label ---"

    # Wait for containers to stabilize
    sleep 15

    # 1. All containers running?
    local running
    running=$(compose ps --format '{{.Service}}\t{{.State}}' 2>/dev/null)
    echo "$running"
    if echo "$running" | grep -qvE "running"; then
        echo "FAIL: not all containers running"
        compose ps -a --format '{{.Service}}\t{{.State}}\t{{.Status}}' 2>/dev/null
        return 1
    fi

    # 2. DNS resolution (retry up to 3 times — CoreDNS may need startup time)
    local cell_id
    cell_id=$(docker ps --filter "label=cagent.role=cell" --format '{{.ID}}' | head -1)
    if [ -z "$cell_id" ]; then
        echo "FAIL: no cell container found"
        return 1
    fi

    local dns_ok=false
    for attempt in 1 2 3; do
        if docker exec "$cell_id" nslookup api.openai.com 2>/dev/null | grep -q "Address"; then
            dns_ok=true
            break
        fi
        echo "DNS attempt $attempt failed, waiting 5s..."
        sleep 5
    done
    if [ "$dns_ok" = "false" ]; then
        echo "FAIL: DNS resolution failed after 3 attempts"
        docker ps -a --filter "name=dns-filter" --format '{{.Names}} {{.Status}}'
        return 1
    fi
    echo "OK: DNS resolves"

    # 3. HTTP proxy chain (cell → Envoy → upstream)
    local http_code
    http_code=$(docker exec "$cell_id" curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 10 http://api.openai.com/v1/models 2>/dev/null || echo "000")
    if [ "$http_code" = "000" ]; then
        echo "FAIL: HTTP proxy chain broken (got 000)"
        return 1
    fi
    echo "OK: HTTP proxy ($http_code)"

    # 4. HTTPS via MITM proxy
    http_code=$(docker exec "$cell_id" curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 10 https://api.github.com/ 2>/dev/null || echo "000")
    if [ "$http_code" = "000" ]; then
        echo "FAIL: MITM proxy chain broken (got 000)"
        return 1
    fi
    echo "OK: MITM proxy ($http_code)"

    # 5. Warden health
    if ! docker exec warden wget -q --spider http://localhost:8080/api/health 2>/dev/null; then
        echo "FAIL: warden unhealthy"
        return 1
    fi
    echo "OK: warden healthy"

    # 6. OpenObserve responding
    sleep 5
    local oz_resp
    oz_resp=$(docker exec log-store wget -q -O - \
        --header="Authorization: Basic $(echo -n 'admin@cagent.local:openobserve-local-dev' | base64)" \
        "http://localhost:5080/api/default/organizations" 2>/dev/null || echo "FAIL")
    if [ "$oz_resp" = "FAIL" ]; then
        echo "FAIL: OpenObserve unreachable"
        return 1
    fi
    echo "OK: OpenObserve responding"

    # 7. Stability — no OOM kills or restarts after 10 more seconds
    sleep 10
    local restart_count
    restart_count=$(docker ps --filter "label=cagent.log-collect=true" \
        --format '{{.Names}} {{.Status}}' | grep -c "Restarting" || true)
    if [ "$restart_count" -gt 0 ]; then
        echo "FAIL: containers restarting"
        return 1
    fi
    echo "OK: stable after 30s total"

    echo "PASS: $label"
    return 0
}

# --- Trial runner ---

run_trial() {
    local label=$1
    shift
    # args: envoy_cpu envoy_mem mitm_cpu mitm_mem vector_cpu vector_mem
    #       warden_cpu warden_mem ozo_cpu ozo_mem dns_mem cell_cpu cell_mem
    local envoy_cpu=$1 envoy_mem=$2 mitm_cpu=$3 mitm_mem=$4
    local vector_cpu=$5 vector_mem=$6 warden_cpu=$7 warden_mem=$8
    local ozo_cpu=$9 ozo_mem=${10} dns_mem=${11}
    local cell_cpu=${12} cell_mem=${13}

    local infra_cpu infra_mem
    infra_cpu=$(echo "$envoy_cpu + $mitm_cpu + $vector_cpu + $warden_cpu + $ozo_cpu + 0.05" | bc)
    infra_mem=$(echo "$envoy_mem + $mitm_mem + $vector_mem + $warden_mem + $ozo_mem + $dns_mem" | bc)

    echo ""
    echo "================================================================"
    echo "TRIAL: $label"
    echo "  Infra: ${infra_cpu} CPU, ${infra_mem}M RAM"
    echo "  Cell:  ${cell_cpu} CPU, ${cell_mem}M RAM"
    echo "  Envoy=${envoy_cpu}/${envoy_mem}M  MITM=${mitm_cpu}/${mitm_mem}M  Vector=${vector_cpu}/${vector_mem}M"
    echo "  Warden=${warden_cpu}/${warden_mem}M  OZO=${ozo_cpu}/${ozo_mem}M  DNS=0.05/${dns_mem}M"
    echo "================================================================"

    write_override "$@"
    teardown
    compose up -d 2>&1

    local result="FAIL"
    if verify "$label"; then
        result="PASS"
    fi

    echo "$label | Infra: ${infra_cpu} CPU ${infra_mem}M | Cell: ${cell_cpu} CPU ${cell_mem}M | $result" | tee -a "$RESULTS"
    teardown
    return $([ "$result" = "PASS" ] && echo 0 || echo 1)
}

# =============================================================================
# Trials — edit these to test different resource allocations
# =============================================================================
# Args: envoy_cpu envoy_mem mitm_cpu mitm_mem vector_cpu vector_mem
#       warden_cpu warden_mem ozo_cpu ozo_mem dns_mem cell_cpu cell_mem

# Generous (50% of original defaults)
run_trial "generous" \
    0.50 256    0.25 128    0.25 128    0.25 256    0.25 256    64    0.50 2752 \
    || true

# Moderate (25% of original defaults)
run_trial "moderate" \
    0.25 128    0.15 96     0.15 96     0.15 192    0.15 192    48    1.15 3088 \
    || true

# Tight (proven minimum with safety margin — current docker-compose defaults)
run_trial "tight" \
    0.10 96     0.10 64     0.10 64     0.10 128    0.10 128    48    1.55 3328 \
    || true

# Floor (absolute minimum that passed in testing)
run_trial "floor" \
    0.05 48     0.05 48     0.05 48     0.10 96     0.10 96     32    1.70 3472 \
    || true

# Below floor (expected to fail — warden/ozo at 64M)
run_trial "below-floor" \
    0.05 48     0.05 48     0.05 48     0.05 64     0.05 64     32    1.80 3568 \
    || true

echo ""
echo "================================================================"
echo "RESULTS SUMMARY"
echo "================================================================"
cat "$RESULTS"
