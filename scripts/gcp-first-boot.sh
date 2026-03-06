#!/usr/bin/env bash
# First-boot script for GCP Marketplace VM images.
# Reads GCE instance metadata, writes /opt/cagent/.env, and starts Docker Compose.
# Runs once via systemd (ConditionPathExists=!/opt/cagent/.env).
set -euo pipefail

METADATA_URL="http://169.254.169.254/computeMetadata/v1/instance/attributes"
METADATA_HEADER="Metadata-Flavor: Google"

get_metadata() {
    local key="$1"
    curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/${key}" || echo ""
}

echo "=== Cagent first-boot: reading GCE metadata ==="

CP_URL=$(get_metadata "cagent-cp-url")
TOKEN=$(get_metadata "cagent-token")
WARDEN_API_TOKEN=$(get_metadata "cagent-warden-api-token")
TLS_CERT_B64=$(get_metadata "cagent-tls-cert")
TLS_KEY_B64=$(get_metadata "cagent-tls-key")
MTLS_CA_CERT_B64=$(get_metadata "cagent-mtls-ca-cert")
SSH_PUBLIC_KEY=$(get_metadata "cagent-ssh-public-key")

if [ -z "$CP_URL" ] || [ -z "$TOKEN" ]; then
    echo "ERROR: Required metadata (cagent-cp-url, cagent-token) not found."
    echo "Ensure the VM was launched with the correct metadata attributes."
    exit 1
fi

# --- Write .env file ---
cat > /opt/cagent/.env <<EOF
DATAPLANE_MODE=connected
CLOUD_PROVIDER=gce
CONTROL_PLANE_URL=${CP_URL}
CONTROL_PLANE_TOKEN=${TOKEN}
WARDEN_API_TOKEN=${WARDEN_API_TOKEN}
BETA_FEATURES=email
EOF

# --- Write mTLS certs if provided ---
if [ -n "$TLS_CERT_B64" ] && [ -n "$TLS_KEY_B64" ] && [ -n "$MTLS_CA_CERT_B64" ]; then
    mkdir -p /opt/cagent/configs/mtls
    echo "$TLS_CERT_B64" | base64 -d > /opt/cagent/configs/mtls/server.crt
    echo "$TLS_KEY_B64" | base64 -d > /opt/cagent/configs/mtls/server.key
    echo "$MTLS_CA_CERT_B64" | base64 -d > /opt/cagent/configs/mtls/ca.crt

    # Add mTLS env vars (base64-encoded PEM for warden)
    {
        echo "WARDEN_TLS_CERT=${TLS_CERT_B64}"
        echo "WARDEN_TLS_KEY=${TLS_KEY_B64}"
        echo "WARDEN_MTLS_CA_CERT=${MTLS_CA_CERT_B64}"
    } >> /opt/cagent/.env
fi

# --- Set up SSH authorized_keys if provided ---
if [ -n "$SSH_PUBLIC_KEY" ]; then
    useradd -m -s /bin/bash cagent 2>/dev/null || true
    usermod -aG docker cagent
    mkdir -p /home/cagent/.ssh
    echo "$SSH_PUBLIC_KEY" > /home/cagent/.ssh/authorized_keys
    chmod 700 /home/cagent/.ssh
    chmod 600 /home/cagent/.ssh/authorized_keys
    chown -R cagent:cagent /home/cagent/.ssh
fi

# --- Generate MITM CA if not present ---
cd /opt/cagent
if [ ! -f configs/mitm/ca.pem ]; then
    bash scripts/gen_mitm_ca.sh
fi

# --- Start Docker Compose ---
echo "=== Starting Cagent services ==="
docker compose \
    --profile dev \
    --profile managed \
    --profile auditing \
    --profile interactive \
    up -d

echo "=== Cagent first-boot complete ==="
