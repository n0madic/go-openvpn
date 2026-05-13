#!/usr/bin/env bash
# gen-pki.sh — generate the PKI + tls-crypt key for the integration-test server.
#
# Everything runs INSIDE an alpine container so the host doesn't need openssl
# or openvpn installed. The resulting files appear under ./pki/ via a bind mount.
#
# Run with no args. Idempotent: if pki/ca.crt already exists, this is a no-op.
set -euo pipefail

PKI="$(cd "$(dirname "$0")" && pwd)/pki"
mkdir -p "$PKI"

if [ -f "$PKI/ca.crt" ] && [ -f "$PKI/tlscrypt.key" ]; then
    echo "PKI already present at $PKI — nothing to do."
    exit 0
fi

echo "Generating PKI at $PKI ..."

docker run --rm -i -v "$PKI":/pki alpine:3.20 sh -eu <<'SH'
apk add --no-cache openvpn openssl > /dev/null

cd /pki

# --- CA ---
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 365 \
    -subj "/CN=go-openvpn-test-ca" -sha256

# --- Server cert (SAN: test-server, localhost, 127.0.0.1) ---
cat > server-ext.cnf <<EOF
extendedKeyUsage = serverAuth
subjectAltName = DNS:test-server, DNS:localhost, IP:127.0.0.1
keyUsage = digitalSignature, keyEncipherment
EOF

openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -out server.csr \
    -subj "/CN=test-server" -sha256
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server-ext.cnf

# --- Client cert ---
cat > client-ext.cnf <<EOF
extendedKeyUsage = clientAuth
keyUsage = digitalSignature
EOF

openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -out client.csr \
    -subj "/CN=test-client" -sha256
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -sha256 -extfile client-ext.cnf

# --- tls-crypt v1 static key ---
openvpn --genkey secret tlscrypt.key

# Cleanup intermediate files.
rm -f *.csr *.srl *-ext.cnf

chmod 644 *
SH

echo "PKI generated:"
ls -la "$PKI"
