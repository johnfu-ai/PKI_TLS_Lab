#!/usr/bin/env bash
set -euo pipefail

CMP_SECRET="${CMP_SHARED_SECRET:-lab-cmp-secret-2026}"

/ca-init.sh

cd /pki

start_mock_cmp() {
  local port="$1"
  local rsp_cert="$2"
  local srv_ref="$3"
  echo "[cmp-mock] Starting CMP responder on :${port} (rsp_cert=${rsp_cert}, ref=${srv_ref})"
  openssl cmp \
    -port "$port" \
    -srv_cert /pki/cmp-srv.cert.pem \
    -srv_key  /pki/cmp-srv.key.pem \
    -srv_secret "pass:${CMP_SECRET}" \
    -srv_ref "$srv_ref" \
    -rsp_cert "/pki/${rsp_cert}" \
    -rsp_capubs /pki/ca-chain.pem \
    -rsp_extracerts /pki/ca-chain.pem \
    -srv_trusted /pki/ca-chain.pem \
    -max_msgs 0 \
    -verbosity 6 &
}

start_mock_cmp 8081 client.cert.pem tlsClient01
start_mock_cmp 8082 server.cert.pem tlsServer01

# Tiny health endpoint on :8080 so other containers can wait on us
( while true; do
    { printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n'; } | nc -lp 8080 -q 1 >/dev/null 2>&1 || sleep 1
  done ) &

echo "[pki-ca] Ready (CMP responders on 8081, 8082)"
wait -n
