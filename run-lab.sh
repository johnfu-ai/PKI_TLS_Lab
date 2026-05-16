#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "${SCRIPT_DIR}/scripts/lib.sh"

load_env
ensure_dirs

PHASE="${1:-all}"
RUN_LOG="${PROJECT_ROOT}/output/run.log"

on_err() {
  log_err "FAILED at line $1 (phase=${PHASE})"
  log_err "See ${RUN_LOG}"
}

on_exit() {
  remove_ephemeral
}

trap 'on_err $LINENO' ERR
trap 'on_exit' EXIT

exec > >(tee -a "${RUN_LOG}") 2>&1

do_build() {
  log_info "Building lab images"
  build_images
}

do_up() {
  do_build
  log_info "Starting pki-ca (EJBCA)"
  docker_compose up -d pki-ca
  wait_container_healthy pki-ca 60 5 || {
    log_err "pki-ca did not become healthy"
    docker logs pki-ca --tail 100
    exit 2
  }
  phase_log bootstrap "${SCRIPT_DIR}/scripts/bootstrap-ca.sh"
}

do_enroll() {
  [[ -f "${PROJECT_ROOT}/output/pki/.ca-bootstrap.done" ]] || {
    log_err "CA not bootstrapped; run: make up"
    exit 1
  }
  phase_log enroll-cmp "${SCRIPT_DIR}/scripts/enroll-cmp.sh" all
}

do_tls12() {
  [[ -f "${PROJECT_ROOT}/output/pki/server.cert.pem" ]] || {
    log_err "Server cert missing; run: make enroll"
    exit 1
  }
  log_info "Starting tls-server"
  docker_compose --profile tls up -d tls-server
  wait_container_healthy tls-server 30 2 || sleep 3
  phase_log tls12 bash -c "
    '${SCRIPT_DIR}/scripts/capture-start.sh' tls12
    '${SCRIPT_DIR}/scripts/tls-handshake.sh' 1.2
    '${SCRIPT_DIR}/scripts/capture-stop.sh' tls12
  "
}

do_tls13() {
  docker_compose --profile tls up -d tls-server 2>/dev/null || true
  wait_container_healthy tls-server 30 2 || sleep 3
  phase_log tls13 bash -c "
    '${SCRIPT_DIR}/scripts/capture-start.sh' tls13
    '${SCRIPT_DIR}/scripts/tls-handshake.sh' 1.3
    '${SCRIPT_DIR}/scripts/capture-stop.sh' tls13
  "
}

do_analyze() {
  phase_log analyze "${SCRIPT_DIR}/scripts/analyze.sh"
}

do_test() {
  do_build
  docker run --rm \
    -v "${PROJECT_ROOT}:/work" -w /work \
    pkilab/analyzer pytest -q tests/
}

do_all() {
  "${SCRIPT_DIR}/scripts/clean.sh"
  ensure_dirs
  do_up
  do_enroll
  do_tls12
  do_tls13
  do_analyze
  log_info "Lab complete. Reports: output/analysis/"
}

case "${PHASE}" in
  build)   do_build ;;
  up)      do_up ;;
  enroll)  do_enroll ;;
  tls12)   do_tls12 ;;
  tls13)   do_tls13 ;;
  analyze) do_analyze ;;
  test)    do_test ;;
  all)     do_all ;;
  *)
    echo "Usage: $0 {build|up|enroll|tls12|tls13|analyze|all|test}" >&2
    exit 1
    ;;
esac
