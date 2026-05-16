#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

load_env
ensure_dirs
build_images 2>/dev/null || true

NAME="${1:?capture name: cmp|tls12|tls13}"
FILTER="${2:-}"

case "$NAME" in
  cmp)
    TARGET=pki-ca
    FILTER="${FILTER:-tcp portrange 8080-8082}"
    ;;
  tls12)
    TARGET=tls-server
    FILTER="${FILTER:-tcp port 4443}"
    ;;
  tls13)
    TARGET=tls-server
    FILTER="${FILTER:-tcp port 4444}"
    ;;
  *)
    log_err "Unknown capture name: $NAME"
    exit 1
    ;;
esac

docker rm -f "capture-${NAME}" 2>/dev/null || true

log_info "Starting capture-${NAME} on container:${TARGET} filter='${FILTER}'"
docker run -d --rm \
  --name "capture-${NAME}" \
  --label "${LAB_LABEL}" \
  --network "container:${TARGET}" \
  -v "${PROJECT_ROOT}/output/pcap:/pcap" \
  pkilab/capture \
  -i any -U -s 0 -w "/pcap/${NAME}.pcap" ${FILTER}

sleep 0.5
