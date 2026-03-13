#!/usr/bin/env bash
# Packer provisioning script for Marketplace VM images (GCP and AWS).
# Runs during image build: installs packages, clones repo, pulls images,
# installs the first-boot systemd service.
set -euo pipefail

CLOUD_PROVIDER="${CLOUD_PROVIDER:-gcp}"
echo "=== Cagent ${CLOUD_PROVIDER} Marketplace image provisioning ==="

# Wait for cloud-init to finish (Packer base image may still be running it)
cloud-init status --wait || true

export DEBIAN_FRONTEND=noninteractive

# --- System packages ---
sudo apt-get update -y
sudo apt-get install -y \
    docker.io \
    docker-compose-v2 \
    fail2ban \
    jq \
    curl \
    ca-certificates \
    git

# Enable Docker
sudo systemctl enable docker
sudo systemctl start docker

# --- Clone cagent repo ---
CAGENT_REPO="${CAGENT_REPO:-https://github.com/kashyaprpuranik/cagent.git}"
CAGENT_BRANCH="${CAGENT_BRANCH:-main}"

sudo git clone --depth 1 --branch "$CAGENT_BRANCH" "$CAGENT_REPO" /opt/cagent
sudo chown -R root:root /opt/cagent

# --- Pre-pull Docker images ---
cd /opt/cagent
sudo docker compose --profile dev --profile managed --profile auditing pull

# --- Install first-boot systemd service ---
sudo cp "/tmp/${CLOUD_PROVIDER}-first-boot.sh" "/opt/cagent/scripts/${CLOUD_PROVIDER}-first-boot.sh"
sudo chmod +x "/opt/cagent/scripts/${CLOUD_PROVIDER}-first-boot.sh"
sudo cp "/tmp/${CLOUD_PROVIDER}-first-boot.service" "/etc/systemd/system/${CLOUD_PROVIDER}-first-boot.service"
sudo systemctl daemon-reload
sudo systemctl enable "${CLOUD_PROVIDER}-first-boot.service"

# --- Cleanup ---
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*

echo "=== Provisioning complete ==="
