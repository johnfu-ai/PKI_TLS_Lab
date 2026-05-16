#!/usr/bin/env bash
# With the new openssl-based pki-ca, the CA bootstrap happens inside the
# container itself (see images/pki-ca/ca-init.sh). This script just waits
# until the container has finished initializing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

load_env
ensure_dirs

log_info "Waiting for pki-ca to finish initializing PKI..."
for i in $(seq 1 30); do
  if [[ -f "${PROJECT_ROOT}/output/pki/.ca-bootstrap.done" ]]; then
    log_info "PKI ready"
    ls -la "${PROJECT_ROOT}/output/pki" | head -20
    exit 0
  fi
  sleep 2
done
log_err "PKI bootstrap did not complete in time"
exit 1
