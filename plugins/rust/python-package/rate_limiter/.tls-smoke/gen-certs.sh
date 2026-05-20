#!/usr/bin/env bash
# Generate a self-signed CA, server cert, and client cert for the
# rate-limiter plugin-level TLS smoke test.
#
# Outputs into ``./.tls-smoke/certs/`` (next to this script).  Re-run is
# idempotent — overwrites any existing files.  The whole ``certs/``
# directory is gitignored.
#
# What gets created:
#
#   ca.crt, ca.key          self-signed CA (4096-bit RSA, 365 days)
#   redis.crt, redis.key    server cert signed by ca.crt
#                           SAN: DNS=localhost, IP=127.0.0.1
#   client.crt, client.key  client cert signed by ca.crt
#                           extendedKeyUsage = clientAuth
#
# The smoke test (``smoke.py``) reads ca.crt for server-cert verification
# and client.{crt,key} for the mTLS combo.

set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

# ---------- CA ----------
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
    -subj "/CN=cpex-rate-limiter-smoke-ca" \
    -out ca.crt

# ---------- Server cert (Redis) ----------
openssl genrsa -out redis.key 2048
openssl req -new -key redis.key -subj "/CN=redis-smoke" -out redis.csr

cat > redis.ext <<'EOF'
subjectAltName = DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in redis.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out redis.crt -days 365 -sha256 \
    -extfile redis.ext

# ---------- Client cert (mTLS) ----------
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=rate-limiter-plugin-client" -out client.csr

cat > client.ext <<'EOF'
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 365 -sha256 \
    -extfile client.ext

# ---------- Cleanup intermediates ----------
rm -f redis.csr redis.ext client.csr client.ext ca.srl

# ---------- Permissions ----------
chmod 0644 ca.crt redis.crt client.crt
chmod 0600 ca.key redis.key client.key

echo
echo "Wrote certs to ${CERT_DIR}:"
ls -la "${CERT_DIR}"
