#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

load_env
ensure_dirs
build_images 2>/dev/null || true

VER="${1:?TLS version: 1.2 or 1.3}"
IP="$(srv_ip)"
if [[ -z "$IP" ]]; then
  log_err "tls-server not running or has no IP"
  exit 1
fi

case "$VER" in
  1.2)
    PORT=4443
    KEYLOG="/pki/sslkeys-tls12.log"
    CURL_TLS=(--tlsv1.2 --tls-max 1.2 --ciphers "${TLS12_CIPHER}")
    HDR="/pki/tls12-headers.txt"
    ;;
  1.3)
    PORT=4444
    KEYLOG="/pki/sslkeys-tls13.log"
    CURL_TLS=(--tlsv1.3 --tls-max 1.3 --tls13-ciphers "${TLS13_CIPHERSUITE}")
    HDR="/pki/tls13-headers.txt"
    ;;
  *)
    log_err "Unknown version: $VER"
    exit 1
    ;;
esac

log_info "TLS ${VER} mTLS handshake to ${SERVER_DNS}:${PORT} (${IP})"

docker run --rm \
  --label "${LAB_LABEL}" \
  --network "${LAB_NETWORK}" \
  -v "${PROJECT_ROOT}/output/pki:/pki" \
  -e SSLKEYLOGFILE="${KEYLOG}" \
  pkilab/tls-client \
  -sS --fail-with-body \
  --resolve "${SERVER_DNS}:${PORT}:${IP}" \
  --cacert /pki/ca-chain.pem \
  --cert /pki/client.cert.pem \
  --key /pki/client.key.pem \
  --curves P-256 \
  "${CURL_TLS[@]}" \
  -D "${HDR}" \
  "https://${SERVER_DNS}:${PORT}/"

log_info "TLS ${VER} complete; keylog ${KEYLOG}"
