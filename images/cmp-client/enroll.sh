#!/usr/bin/env bash
set -euo pipefail

ROLE="${ROLE:?ROLE required (client|server)}"
CMP_SECRET="${CMP_SHARED_SECRET:-lab-cmp-secret-2026}"

case "$ROLE" in
  client)
    PORT=8081
    REF="tlsClient01"
    SUBJECT="/C=US/O=PKI_TLS_Lab/CN=tls-client.lab.local"
    ;;
  server)
    PORT=8082
    REF="tlsServer01"
    SUBJECT="/C=US/O=PKI_TLS_Lab/CN=tls-server.lab.local"
    ;;
  *)
    echo "Unknown ROLE: $ROLE" >&2
    exit 1
    ;;
esac

CMP_URL="http://pki-ca:${PORT}/"

if [[ ! -f /pki/ca-chain.pem ]]; then
  echo "Missing /pki/ca-chain.pem — pki-ca must run first" >&2
  exit 1
fi

WORK=/tmp/${ROLE}-cmp
mkdir -p "$WORK"
cd "$WORK"

echo "=== ${ROLE}: ECDSA P-256 keypair ==="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out new.key.pem

echo "=== ${ROLE}: CMP Initialization Request (ir) with implicit_confirm ==="
openssl cmp \
  -cmd ir \
  -server "${CMP_URL}" \
  -ref "${REF}" \
  -secret "pass:${CMP_SECRET}" \
  -recipient "/C=US/O=PKI_TLS_Lab/CN=LabRootCA" \
  -subject "${SUBJECT}" \
  -newkey new.key.pem \
  -certout "/tmp/${ROLE}.cert.pem" \
  -extracertsout "/tmp/${ROLE}.chain.pem" \
  -trusted /pki/ca-chain.pem \
  -popo 1 \
  -implicit_confirm \
  -verbosity 6

echo "=== ${ROLE}: CMP Certificate Request (cr) — full 4-message exchange ==="
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out new2.key.pem
openssl cmp \
  -cmd cr \
  -server "${CMP_URL}" \
  -ref "${REF}" \
  -secret "pass:${CMP_SECRET}" \
  -recipient "/C=US/O=PKI_TLS_Lab/CN=LabRootCA" \
  -subject "${SUBJECT}" \
  -newkey new2.key.pem \
  -certout "/tmp/${ROLE}.cr.cert.pem" \
  -trusted /pki/ca-chain.pem \
  -popo 1 \
  -verbosity 6 || echo "[note] cr exchange may complete with status pending; PKI traffic still captured"

echo "=== ${ROLE}: CMP enrollment complete ==="
