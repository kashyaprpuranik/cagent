#!/bin/bash
# =============================================================================
# Load Static Configuration
# =============================================================================
# Converts static-config.yaml to environment variables for Envoy
#
# Usage:
#   source scripts/load-static-config.sh
#   docker-compose up -d
#
# Or inline:
#   eval $(scripts/load-static-config.sh --export)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../configs/static-config.yaml"

# Check if config exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "# No static config found at $CONFIG_FILE" >&2
    exit 0
fi

# Check for yq (YAML parser)
if ! command -v yq &> /dev/null; then
    echo "# Warning: yq not installed, cannot parse YAML config" >&2
    echo "# Install with: sudo snap install yq" >&2
    exit 0
fi

# Parse domain mappings
DOMAIN_MAP=""
while IFS=': ' read -r key value; do
    if [[ -n "$key" && -n "$value" ]]; then
        if [[ -n "$DOMAIN_MAP" ]]; then
            DOMAIN_MAP="${DOMAIN_MAP},"
        fi
        DOMAIN_MAP="${DOMAIN_MAP}${key}:${value}"
    fi
done < <(yq -r '.domain_mappings // {} | to_entries | .[] | "\(.key): \(.value)"' "$CONFIG_FILE" 2>/dev/null)

# Parse credentials (pipe-separated because values may contain colons)
CREDENTIALS=""
while IFS= read -r line; do
    domain=$(echo "$line" | yq -r '.domain_pattern // empty')
    header_name=$(echo "$line" | yq -r '.header_name // "Authorization"')
    header_value=$(echo "$line" | yq -r '.header_value // empty')

    if [[ -n "$domain" && -n "$header_value" ]]; then
        if [[ -n "$CREDENTIALS" ]]; then
            CREDENTIALS="${CREDENTIALS}|"
        fi
        CREDENTIALS="${CREDENTIALS}${domain}:${header_name}:${header_value}"
    fi
done < <(yq -r '.credentials // [] | .[]' "$CONFIG_FILE" 2>/dev/null)

# Parse rate limits
RATE_LIMITS=""

# Default rate limit
default_rpm=$(yq -r '.rate_limits.default.requests_per_minute // 120' "$CONFIG_FILE" 2>/dev/null)
default_burst=$(yq -r '.rate_limits.default.burst_size // 20' "$CONFIG_FILE" 2>/dev/null)
RATE_LIMITS="default:${default_rpm}:${default_burst}"

# Domain-specific rate limits
while IFS= read -r domain; do
    rpm=$(yq -r ".rate_limits.domains[\"$domain\"].requests_per_minute // 60" "$CONFIG_FILE" 2>/dev/null)
    burst=$(yq -r ".rate_limits.domains[\"$domain\"].burst_size // 10" "$CONFIG_FILE" 2>/dev/null)
    RATE_LIMITS="${RATE_LIMITS},${domain}:${rpm}:${burst}"
done < <(yq -r '.rate_limits.domains // {} | keys | .[]' "$CONFIG_FILE" 2>/dev/null)

# Output
if [[ "$1" == "--export" ]]; then
    echo "export STATIC_DOMAIN_MAP='${DOMAIN_MAP}'"
    echo "export STATIC_CREDENTIALS='${CREDENTIALS}'"
    echo "export STATIC_RATE_LIMITS='${RATE_LIMITS}'"
else
    echo "# Static configuration loaded from $CONFIG_FILE"
    echo "STATIC_DOMAIN_MAP='${DOMAIN_MAP}'"
    echo "STATIC_CREDENTIALS='${CREDENTIALS}'"
    echo "STATIC_RATE_LIMITS='${RATE_LIMITS}'"
fi
