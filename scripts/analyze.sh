#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

load_env
ensure_dirs
build_images 2>/dev/null || true

log_info "Running protocol analyzer (offline)"

docker run --rm \
  --network none \
  -v "${PROJECT_ROOT}/output:/output:rw" \
  pkilab/analyzer \
  python -m analyzer \
    --pcap-dir /output/pcap \
    --keylog-dir /output/pki \
    --pki-dir /output/pki \
    --out-dir /output/analysis

log_info "Reports written to output/analysis/"
