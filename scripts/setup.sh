#!/bin/bash
# Pre-compose setup: generate cert files needed by Docker Compose services.
# Called by local.sh, test.sh, gcp-first-boot.sh, and Hetzner cloud-init.
#
# - MITM CA: always generated (idempotent)
# - mTLS certs: skipped if CP already provided them via WARDEN_TLS_CERT env var
set -e
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# MITM CA (always — idempotent)
bash "$ROOT_DIR/scripts/gen_mitm_ca.sh"

# mTLS certs (skip if CP provided them via env vars)
if [ -z "${WARDEN_TLS_CERT:-}" ]; then
    bash "$ROOT_DIR/scripts/gen_mtls_certs.sh"
fi
