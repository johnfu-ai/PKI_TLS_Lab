#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

NAME="${1:?capture name: cmp|tls12|tls13}"
PCAP="${PROJECT_ROOT}/output/pcap/${NAME}.pcap"

log_info "Stopping capture-${NAME}"
docker stop --signal=SIGTERM --time=5 "capture-${NAME}" >/dev/null 2>&1 || true
sleep 0.3

if [[ ! -s "$PCAP" ]]; then
  log_warn "pcap missing or empty: $PCAP (lab may still proceed for analyze dry-run)"
else
  log_info "pcap saved: $PCAP ($(wc -c <"$PCAP") bytes)"
fi
