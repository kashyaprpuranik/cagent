#!/bin/bash
# =============================================================================
# Generate CA certificate for mitmproxy TLS interception
# =============================================================================
#
# Generates a self-signed CA cert+key that mitmproxy uses to dynamically
# sign certificates for intercepted HTTPS connections.
#
# Output files in configs/mitm/:
#   mitmproxy-ca.pem         Combined key+cert (mitmproxy confdir format)
#   mitmproxy-ca-cert.pem    Cert only (mounted into cell as trusted CA)
#
# Idempotent: skips generation if a valid cert already exists.
# =============================================================================

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MITM_DIR="$ROOT_DIR/configs/mitm"
CA_PEM="$MITM_DIR/mitmproxy-ca.pem"
CA_CERT="$MITM_DIR/mitmproxy-ca-cert.pem"

# Check if valid cert already exists
if [ -f "$CA_PEM" ] && [ -f "$CA_CERT" ]; then
    # Verify cert is not expired (valid for at least 1 more day)
    if openssl x509 -in "$CA_CERT" -checkend 86400 -noout 2>/dev/null; then
        echo "MITM CA certificate already exists and is valid, skipping generation."
        exit 0
    fi
    echo "MITM CA certificate expired, regenerating..."
fi

echo "Generating MITM CA certificate..."
mkdir -p "$MITM_DIR"

# Generate CA key + cert (valid for 1 year)
openssl req -x509 -newkey rsa:2048 \
    -keyout "$MITM_DIR/mitmproxy-ca-key.pem" \
    -out "$CA_CERT" \
    -days 365 \
    -nodes \
    -subj "/CN=cagent-mitm-ca/O=Cagent MITM Proxy" \
    2>/dev/null

# Combine key+cert into single file (mitmproxy confdir format)
cat "$MITM_DIR/mitmproxy-ca-key.pem" "$CA_CERT" > "$CA_PEM"

# Set permissions: key is sensitive, cert is public
chmod 600 "$CA_PEM" "$MITM_DIR/mitmproxy-ca-key.pem"
chmod 644 "$CA_CERT"

# Clean up standalone key file (combined PEM is the source of truth)
rm -f "$MITM_DIR/mitmproxy-ca-key.pem"

echo "MITM CA certificate generated:"
echo "  Key+Cert: $CA_PEM"
echo "  Cert only: $CA_CERT"
