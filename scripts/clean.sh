#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

load_env
log_info "Stopping lab containers and removing output/"

remove_ephemeral
docker rm -f capture-cmp capture-tls12 capture-tls13 2>/dev/null || true
docker compose -f "${PROJECT_ROOT}/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true
docker network rm "${LAB_NETWORK}" 2>/dev/null || true

rm -rf "${PROJECT_ROOT}/output"

log_info "Clean complete."
