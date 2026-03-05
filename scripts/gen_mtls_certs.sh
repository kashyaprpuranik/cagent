#!/bin/bash
# =============================================================================
# Generate mTLS certificates for warden CP-to-DP communication
# =============================================================================
#
# Generates a self-signed CA, server cert, and client cert for testing
# warden's mTLS listener locally. Mirrors gen_mitm_ca.sh pattern.
#
# Output files in configs/mtls/:
#   ca-cert.pem / ca-key.pem           CA that signs both certs
#   server-cert.pem / server-key.pem   Warden presents to clients
#   client-cert.pem / client-key.pem   For testing with curl
#
# Idempotent: skips generation if valid certs already exist.
# =============================================================================

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MTLS_DIR="$ROOT_DIR/configs/mtls"
CA_CERT="$MTLS_DIR/ca-cert.pem"
CA_KEY="$MTLS_DIR/ca-key.pem"
SERVER_CERT="$MTLS_DIR/server-cert.pem"
SERVER_KEY="$MTLS_DIR/server-key.pem"
CLIENT_CERT="$MTLS_DIR/client-cert.pem"
CLIENT_KEY="$MTLS_DIR/client-key.pem"

# Check if valid certs already exist
if [ -f "$CA_CERT" ] && [ -f "$SERVER_CERT" ] && [ -f "$CLIENT_CERT" ]; then
    if openssl x509 -in "$CA_CERT" -checkend 86400 -noout 2>/dev/null && \
       openssl x509 -in "$SERVER_CERT" -checkend 86400 -noout 2>/dev/null && \
       openssl x509 -in "$CLIENT_CERT" -checkend 86400 -noout 2>/dev/null; then
        echo "mTLS certificates already exist and are valid, skipping generation."
        exit 0
    fi
    echo "mTLS certificates expired or expiring soon, regenerating..."
fi

echo "Generating mTLS certificates..."
mkdir -p "$MTLS_DIR"

# --- CA ---
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CA_KEY" \
    -out "$CA_CERT" \
    -days 365 \
    -nodes \
    -subj "/CN=cagent-mtls-ca/O=Cagent mTLS"

# --- Server cert (warden) ---
openssl req -newkey rsa:2048 \
    -keyout "$SERVER_KEY" \
    -out "$MTLS_DIR/server.csr" \
    -nodes \
    -subj "/CN=localhost/O=Cagent Warden"

cat > "$MTLS_DIR/server-ext.cnf" <<EOF
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:10.200.2.2
EOF

openssl x509 -req \
    -in "$MTLS_DIR/server.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$SERVER_CERT" \
    -days 365 \
    -extfile "$MTLS_DIR/server-ext.cnf"

# --- Client cert (for testing) ---
openssl req -newkey rsa:2048 \
    -keyout "$CLIENT_KEY" \
    -out "$MTLS_DIR/client.csr" \
    -nodes \
    -subj "/CN=cagent-client/O=Cagent Client"

openssl x509 -req \
    -in "$MTLS_DIR/client.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$CLIENT_CERT" \
    -days 365

# --- Cleanup temp files ---
rm -f "$MTLS_DIR"/*.csr "$MTLS_DIR"/*.cnf "$MTLS_DIR"/*.srl

# --- Permissions ---
chmod 600 "$CA_KEY" "$SERVER_KEY" "$CLIENT_KEY"
chmod 644 "$CA_CERT" "$SERVER_CERT" "$CLIENT_CERT"

echo "mTLS certificates generated in $MTLS_DIR:"
echo "  CA:     $CA_CERT / $CA_KEY"
echo "  Server: $SERVER_CERT / $SERVER_KEY"
echo "  Client: $CLIENT_CERT / $CLIENT_KEY"
