#!/usr/bin/env bash
# First-boot script for AWS Marketplace VM images.
# Reads EC2 user data (plain-text env file), writes /opt/cagent/.env,
# and starts Docker Compose.
# Runs once via systemd (ConditionPathExists=!/opt/cagent/.env).
set -euo pipefail

echo "=== Cagent first-boot: reading EC2 user data ==="

# IMDSv2: get session token first
IMDS_TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 300")

USER_DATA=$(curl -sf -H "X-aws-ec2-metadata-token: ${IMDS_TOKEN}" \
    "http://169.254.169.254/latest/user-data" || echo "")

if [ -z "$USER_DATA" ]; then
    echo "ERROR: No EC2 user data found."
    echo "Ensure the instance was launched with the correct user data."
    exit 1
fi

# User data is a plain-text env file from the CP's build_user_data_env().
# Validate required keys are present.
if ! echo "$USER_DATA" | grep -q "^CONTROL_PLANE_URL="; then
    echo "ERROR: User data missing CONTROL_PLANE_URL."
    exit 1
fi
if ! echo "$USER_DATA" | grep -q "^CONTROL_PLANE_TOKEN="; then
    echo "ERROR: User data missing CONTROL_PLANE_TOKEN."
    exit 1
fi

# Validate no newline injection in values
while IFS='=' read -r key value; do
    # Skip empty lines and comments
    [ -z "$key" ] && continue
    [[ "$key" == \#* ]] && continue
    if [[ "$value" == *$'\r'* ]]; then
        echo "ERROR: Value for ${key} contains carriage return — rejecting."
        exit 1
    fi
done <<< "$USER_DATA"

# --- Extract optional fields before writing .env ---
SSH_AUTHORIZED_KEYS=$(echo "$USER_DATA" | grep "^SSH_AUTHORIZED_KEYS=" | cut -d'=' -f2- || echo "")
TLS_CERT_B64=$(echo "$USER_DATA" | grep "^WARDEN_TLS_CERT=" | cut -d'=' -f2- || echo "")
TLS_KEY_B64=$(echo "$USER_DATA" | grep "^WARDEN_TLS_KEY=" | cut -d'=' -f2- || echo "")
MTLS_CA_CERT_B64=$(echo "$USER_DATA" | grep "^WARDEN_MTLS_CA_CERT=" | cut -d'=' -f2- || echo "")

# --- Write .env file (strip SSH_AUTHORIZED_KEYS, it's not a Docker env var) ---
echo "$USER_DATA" | grep -v "^SSH_AUTHORIZED_KEYS=" > /opt/cagent/.env

# Ensure BETA_FEATURES=email is present
if ! grep -q "^BETA_FEATURES=" /opt/cagent/.env; then
    echo "BETA_FEATURES=email" >> /opt/cagent/.env
fi

# --- Write mTLS certs if provided ---
if [ -n "$TLS_CERT_B64" ] && [ -n "$TLS_KEY_B64" ] && [ -n "$MTLS_CA_CERT_B64" ]; then
    mkdir -p /opt/cagent/configs/mtls
    echo "$TLS_CERT_B64" | base64 -d > /opt/cagent/configs/mtls/server.crt
    echo "$TLS_KEY_B64" | base64 -d > /opt/cagent/configs/mtls/server.key
    echo "$MTLS_CA_CERT_B64" | base64 -d > /opt/cagent/configs/mtls/ca.crt
fi

# --- Set up SSH authorized_keys if provided ---
if [ -n "$SSH_AUTHORIZED_KEYS" ]; then
    useradd -m -s /bin/bash cagent 2>/dev/null || true
    usermod -aG docker cagent
    mkdir -p /home/cagent/.ssh
    echo "$SSH_AUTHORIZED_KEYS" > /home/cagent/.ssh/authorized_keys
    chmod 700 /home/cagent/.ssh
    chmod 600 /home/cagent/.ssh/authorized_keys
    chown -R cagent:cagent /home/cagent/.ssh
fi

# --- Generate certs (MITM CA + mTLS if not provided by CP) ---
cd /opt/cagent
[ -n "$TLS_CERT_B64" ] && export WARDEN_TLS_CERT="$TLS_CERT_B64"
bash scripts/setup.sh

# --- Start Docker Compose ---
echo "=== Starting Cagent services ==="
docker compose \
    --profile dev \
    --profile managed \
    --profile auditing \
    up -d

echo "=== Cagent first-boot complete ==="
