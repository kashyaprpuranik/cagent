#!/bin/bash
# =============================================================================
# Vault Initialization Script
# Sets up secrets engine and policies for AI Devbox
# =============================================================================

set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
export VAULT_ADDR

echo "=== Vault Initialization ==="
echo "Vault Address: $VAULT_ADDR"

# Wait for Vault to be ready
echo "[*] Waiting for Vault to start..."
until curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; do
    sleep 2
done
echo "[+] Vault is ready"

# Check if already initialized
INIT_STATUS=$(curl -s "$VAULT_ADDR/v1/sys/init" | jq -r '.initialized')

if [ "$INIT_STATUS" = "false" ]; then
    echo "[*] Initializing Vault..."
    
    # Initialize with 1 key share (for dev, use 5 shares in production)
    INIT_RESPONSE=$(curl -s -X PUT "$VAULT_ADDR/v1/sys/init" \
        -H "Content-Type: application/json" \
        -d '{"secret_shares": 1, "secret_threshold": 1}')
    
    # Extract keys
    UNSEAL_KEY=$(echo "$INIT_RESPONSE" | jq -r '.keys[0]')
    ROOT_TOKEN=$(echo "$INIT_RESPONSE" | jq -r '.root_token')
    
    # Save keys (in production, distribute these securely!)
    echo "$UNSEAL_KEY" > /vault/config/unseal-key
    echo "$ROOT_TOKEN" > /vault/config/root-token
    chmod 600 /vault/config/unseal-key /vault/config/root-token
    
    echo "[+] Vault initialized"
    echo "[!] IMPORTANT: Secure the unseal key and root token!"
else
    echo "[+] Vault already initialized"
    UNSEAL_KEY=$(cat /vault/config/unseal-key 2>/dev/null || echo "")
    ROOT_TOKEN=$(cat /vault/config/root-token 2>/dev/null || echo "")
fi

# Unseal if needed
SEAL_STATUS=$(curl -s "$VAULT_ADDR/v1/sys/seal-status" | jq -r '.sealed')

if [ "$SEAL_STATUS" = "true" ]; then
    echo "[*] Unsealing Vault..."
    curl -s -X PUT "$VAULT_ADDR/v1/sys/unseal" \
        -H "Content-Type: application/json" \
        -d "{\"key\": \"$UNSEAL_KEY\"}" > /dev/null
    echo "[+] Vault unsealed"
fi

# Login with root token
export VAULT_TOKEN="$ROOT_TOKEN"

# -----------------------------------------------------------------------------
# Enable secrets engines
# -----------------------------------------------------------------------------

echo "[*] Configuring secrets engines..."

# KV v2 secrets engine for API keys
curl -s -X POST "$VAULT_ADDR/v1/sys/mounts/secret" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type": "kv", "options": {"version": "2"}}' 2>/dev/null || true

# Transit engine for encryption
curl -s -X POST "$VAULT_ADDR/v1/sys/mounts/transit" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type": "transit"}' 2>/dev/null || true

echo "[+] Secrets engines configured"

# -----------------------------------------------------------------------------
# Create policies
# -----------------------------------------------------------------------------

echo "[*] Creating policies..."

# AI Agent policy - read-only access to specific secrets
cat > /tmp/ai-agent-policy.hcl << 'EOF'
# AI Agent can read API keys
path "secret/data/ai-devbox/*" {
  capabilities = ["read"]
}

# Can list available secrets
path "secret/metadata/ai-devbox/*" {
  capabilities = ["list"]
}

# Can use transit for encryption/decryption
path "transit/encrypt/ai-devbox" {
  capabilities = ["update"]
}

path "transit/decrypt/ai-devbox" {
  capabilities = ["update"]
}
EOF

curl -s -X PUT "$VAULT_ADDR/v1/sys/policies/acl/ai-agent" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"policy\": $(cat /tmp/ai-agent-policy.hcl | jq -Rs .)}"

# Admin policy
cat > /tmp/admin-policy.hcl << 'EOF'
# Full access to ai-devbox secrets
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/mounts" {
  capabilities = ["read", "list"]
}

path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

curl -s -X PUT "$VAULT_ADDR/v1/sys/policies/acl/admin" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"policy\": $(cat /tmp/admin-policy.hcl | jq -Rs .)}"

echo "[+] Policies created"

# -----------------------------------------------------------------------------
# Enable AppRole authentication (for automated access)
# -----------------------------------------------------------------------------

echo "[*] Configuring AppRole authentication..."

curl -s -X POST "$VAULT_ADDR/v1/sys/auth/approle" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type": "approle"}' 2>/dev/null || true

# Create role for AI agent
curl -s -X POST "$VAULT_ADDR/v1/auth/approle/role/ai-agent" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "token_policies": ["ai-agent"],
        "token_ttl": "1h",
        "token_max_ttl": "4h",
        "secret_id_ttl": "24h",
        "secret_id_num_uses": 0
    }'

# Get Role ID
ROLE_ID=$(curl -s "$VAULT_ADDR/v1/auth/approle/role/ai-agent/role-id" \
    -H "X-Vault-Token: $VAULT_TOKEN" | jq -r '.data.role_id')

# Generate Secret ID
SECRET_ID=$(curl -s -X POST "$VAULT_ADDR/v1/auth/approle/role/ai-agent/secret-id" \
    -H "X-Vault-Token: $VAULT_TOKEN" | jq -r '.data.secret_id')

echo "$ROLE_ID" > /vault/config/agent-role-id
echo "$SECRET_ID" > /vault/config/agent-secret-id
chmod 600 /vault/config/agent-role-id /vault/config/agent-secret-id

echo "[+] AppRole configured"

# -----------------------------------------------------------------------------
# Create encryption key for transit
# -----------------------------------------------------------------------------

echo "[*] Creating encryption key..."

curl -s -X POST "$VAULT_ADDR/v1/transit/keys/ai-devbox" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type": "aes256-gcm96"}' 2>/dev/null || true

echo "[+] Encryption key created"

# -----------------------------------------------------------------------------
# Add sample secrets (remove in production!)
# -----------------------------------------------------------------------------

echo "[*] Adding sample secrets..."

# These are EXAMPLES - replace with real secrets in production
curl -s -X POST "$VAULT_ADDR/v1/secret/data/ai-devbox/api-keys" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "OPENAI_API_KEY": "sk-placeholder-replace-me",
            "ANTHROPIC_API_KEY": "sk-ant-placeholder-replace-me",
            "HUGGINGFACE_TOKEN": "hf_placeholder-replace-me",
            "GITHUB_TOKEN": "ghp_placeholder-replace-me"
        }
    }'

curl -s -X POST "$VAULT_ADDR/v1/secret/data/ai-devbox/database" \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "data": {
            "DATABASE_URL": "postgresql://user:pass@localhost:5432/db",
            "REDIS_URL": "redis://localhost:6379"
        }
    }'

echo "[+] Sample secrets added"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

echo ""
echo "=== Vault Setup Complete ==="
echo ""
echo "Vault UI:     $VAULT_ADDR/ui"
echo "Root Token:   (stored in /vault/config/root-token)"
echo ""
echo "AI Agent AppRole:"
echo "  Role ID:    $ROLE_ID"
echo "  Secret ID:  (stored in /vault/config/agent-secret-id)"
echo ""
echo "To authenticate as AI agent:"
echo "  curl -X POST $VAULT_ADDR/v1/auth/approle/login \\"
echo "    -d '{\"role_id\": \"$ROLE_ID\", \"secret_id\": \"<secret>\"}'"
echo ""
echo "To read a secret:"
echo "  curl -H 'X-Vault-Token: <token>' \\"
echo "    $VAULT_ADDR/v1/secret/data/ai-devbox/api-keys"
