#!/usr/bin/env bash
# =============================================================================
# WID Federation CA — Generate CA Keypair for mTLS Relay Authentication
# =============================================================================
#
# This script generates an ECDSA P-256 CA keypair used to sign relay
# client certificates in the bootstrap flow (when SPIRE is not available).
#
# Usage:
#   ./generate-federation-ca.sh [output-dir]
#
# Output:
#   federation-ca-key.pem  — CA private key (KEEP SECRET)
#   federation-ca-cert.pem — CA certificate (distribute to relays as CA bundle)
#
# The CA certificate should be:
#   1. Stored securely (Vault, KMS, Secrets Manager)
#   2. Set as FEDERATION_CA_KEY_PATH and FEDERATION_CA_CERT_PATH on the hub
#   3. Set as RELAY_CA_BUNDLE_PATH on spoke relays
#
# =============================================================================
set -euo pipefail

OUTPUT_DIR="${1:-.}"
mkdir -p "$OUTPUT_DIR"

CA_KEY="$OUTPUT_DIR/federation-ca-key.pem"
CA_CERT="$OUTPUT_DIR/federation-ca-cert.pem"
VALIDITY_DAYS=365

echo "Generating WID Federation CA..."
echo "  Output: $OUTPUT_DIR"
echo "  Algorithm: ECDSA P-256"
echo "  Validity: ${VALIDITY_DAYS} days"
echo ""

# Generate EC private key
openssl ecparam -genkey -name prime256v1 -noout -out "$CA_KEY"

# Generate self-signed CA certificate
openssl req -new -x509 \
  -key "$CA_KEY" \
  -out "$CA_CERT" \
  -days "$VALIDITY_DAYS" \
  -subj "/CN=WID Federation CA/O=WID Platform/OU=Federation" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# Verify
echo "CA Certificate:"
openssl x509 -in "$CA_CERT" -noout -text | grep -E "(Subject:|Issuer:|Not Before|Not After|Public Key Algorithm)"
echo ""

# Compute fingerprint
FINGERPRINT=$(openssl x509 -in "$CA_CERT" -outform DER | sha256sum | awk '{print $1}')
echo "CA Fingerprint (SHA-256): $FINGERPRINT"
echo ""

echo "Files generated:"
echo "  Private key: $CA_KEY (KEEP SECRET)"
echo "  Certificate: $CA_CERT (distribute to relays)"
echo ""
echo "Hub configuration:"
echo "  FEDERATION_CA_KEY_PATH=$CA_KEY"
echo "  FEDERATION_CA_CERT_PATH=$CA_CERT"
echo ""
echo "Spoke relay configuration:"
echo "  RELAY_CA_BUNDLE_PATH=$CA_CERT"
echo ""

# Generate a sample relay client cert (for testing)
if [[ "${2:-}" == "--with-relay-cert" ]]; then
  RELAY_KEY="$OUTPUT_DIR/relay-key.pem"
  RELAY_CERT="$OUTPUT_DIR/relay-cert.pem"
  RELAY_CSR="$OUTPUT_DIR/relay.csr"
  RELAY_ENV="${3:-test-relay}"

  echo "Generating sample relay certificate for: $RELAY_ENV"

  # Generate relay keypair
  openssl ecparam -genkey -name prime256v1 -noout -out "$RELAY_KEY"

  # Create CSR with SPIFFE SAN
  openssl req -new \
    -key "$RELAY_KEY" \
    -out "$RELAY_CSR" \
    -subj "/CN=$RELAY_ENV/O=WID Platform/OU=Relay" \
    -addext "subjectAltName=URI:spiffe://wid-platform/relay/$RELAY_ENV"

  # Sign with CA
  openssl x509 -req \
    -in "$RELAY_CSR" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$RELAY_CERT" \
    -days 1 \
    -copy_extensions copyall

  rm -f "$RELAY_CSR" "$OUTPUT_DIR/federation-ca-cert.srl"

  echo "Relay certificate generated:"
  echo "  Private key: $RELAY_KEY"
  echo "  Certificate: $RELAY_CERT (1 day validity)"
  echo ""
  echo "Relay configuration:"
  echo "  RELAY_CERT_PATH=$RELAY_CERT"
  echo "  RELAY_KEY_PATH=$RELAY_KEY"
  echo "  RELAY_CA_BUNDLE_PATH=$CA_CERT"
fi
