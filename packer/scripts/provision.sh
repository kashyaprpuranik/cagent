#!/usr/bin/env bash
# Packer provisioning script for the GCP Marketplace VM image.
# Runs during image build: installs packages, clones repo, pulls images,
# installs the first-boot systemd service.
set -euo pipefail

echo "=== Cagent GCP Marketplace image provisioning ==="

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
sudo docker compose --profile dev --profile managed --profile auditing --profile interactive pull || true

# --- Install first-boot systemd service ---
sudo cp /tmp/gcp-first-boot.sh /opt/cagent/scripts/gcp-first-boot.sh
sudo chmod +x /opt/cagent/scripts/gcp-first-boot.sh
sudo cp /tmp/gcp-first-boot.service /etc/systemd/system/gcp-first-boot.service
sudo systemctl daemon-reload
sudo systemctl enable gcp-first-boot.service

# --- Cleanup ---
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*

echo "=== Provisioning complete ==="
