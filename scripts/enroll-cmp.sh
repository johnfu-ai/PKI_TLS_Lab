#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

load_env
ensure_dirs
build_images 2>/dev/null || true

TARGET="${1:-all}"

run_enroll() {
  local role="$1"
  log_info "CMP enroll: ${role}"
  docker run --rm \
    --label "${LAB_LABEL}" \
    --network "${LAB_NETWORK}" \
    -v "${PROJECT_ROOT}/output/pki:/pki" \
    -e ROLE="${role}" \
    -e CMP_SHARED_SECRET="${CMP_SHARED_SECRET}" \
    -e SERVER_DNS="${SERVER_DNS}" \
    -e CLIENT_DNS="${CLIENT_DNS}" \
    pkilab/cmp-client
  touch "${PROJECT_ROOT}/output/pki/.enroll-${role}.done"
}

if [[ "${TARGET}" == "all" ]]; then
  "${SCRIPT_DIR}/capture-start.sh" cmp || true
  run_enroll client
  run_enroll server
  "${SCRIPT_DIR}/capture-stop.sh" cmp || true
else
  run_enroll "${TARGET}"
fi
