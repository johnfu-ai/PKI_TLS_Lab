#!/usr/bin/env bash
# Shared helpers for PKI_TLS_Lab orchestration scripts.

LAB_LABEL="${LAB_LABEL:-pkilab=true}"
LAB_NETWORK="${LAB_NETWORK:-pkilab_net}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Prefer project docker wrapper (Docker Desktop on WSL without integration)
if [[ -x "${PROJECT_ROOT}/bin/docker" ]]; then
  export PATH="${PROJECT_ROOT}/bin:${PATH}"
fi

# shellcheck source=/dev/null
load_env() {
  if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${PROJECT_ROOT}/.env"
    set +a
  elif [[ -f "${PROJECT_ROOT}/.env.example" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "${PROJECT_ROOT}/.env.example"
    set +a
  fi
  CMP_SHARED_SECRET="${CMP_SHARED_SECRET:-lab-cmp-secret-2026}"
  SERVER_DNS="${SERVER_DNS:-tls-server.lab.local}"
  CLIENT_DNS="${CLIENT_DNS:-tls-client.lab.local}"
  TLS12_CIPHER="${TLS12_CIPHER:-ECDHE-ECDSA-AES256-GCM-SHA384}"
  TLS13_CIPHERSUITE="${TLS13_CIPHERSUITE:-TLS_AES_256_GCM_SHA384}"
}

log() {
  local level="$1"
  shift
  printf '[%s][%s] %s\n' "$(date +%H:%M:%S)" "$level" "$*" >&2
}

log_info()  { log INFO "$@"; }
log_warn()  { log WARN "$@"; }
log_err()   { log ERR  "$@"; }

ensure_dirs() {
  mkdir -p "${PROJECT_ROOT}/output/pki" \
           "${PROJECT_ROOT}/output/pcap" \
           "${PROJECT_ROOT}/output/analysis" \
           "${PROJECT_ROOT}/output/logs"
}

docker_compose() {
  # Run compose from project root so relative volume paths resolve correctly
  (cd "${PROJECT_ROOT}" && docker compose "$@")
}

container_ip() {
  local name="$1"
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null || true
}

srv_ip() {
  container_ip tls-server
}

wait_http() {
  local url="$1"
  local retries="${2:-60}"
  local delay="${3:-5}"
  local i
  for ((i = 1; i <= retries; i++)); do
    if docker run --rm --network "${LAB_NETWORK}" curlimages/curl:8.11.1 \
      -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

wait_container_healthy() {
  local name="$1"
  local retries="${2:-60}"
  local delay="${3:-5}"
  local i status
  for ((i = 1; i <= retries; i++)); do
    status="$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo none)"
    if [[ "$status" == "healthy" ]]; then
      return 0
    fi
    if [[ "$status" == "none" ]]; then
      if docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; then
        return 0
      fi
    fi
    sleep "$delay"
  done
  return 1
}

ephemeral_containers() {
  docker ps -aq --filter "label=${LAB_LABEL}" 2>/dev/null || true
}

remove_ephemeral() {
  local ids
  ids="$(ephemeral_containers)"
  if [[ -n "$ids" ]]; then
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
}

phase_log() {
  local phase="$1"
  shift
  local logfile="${PROJECT_ROOT}/output/logs/${phase}.log"
  mkdir -p "${PROJECT_ROOT}/output/logs"
  "$@" 2>&1 | tee -a "$logfile"
}

# Convert paths for Docker Desktop on Windows when running from WSL (/mnt/c/...)
docker_path() {
  local p="$1"
  if [[ -x "${PROJECT_ROOT}/bin/docker" ]] && command -v wslpath >/dev/null 2>&1; then
    wslpath -w "$p" 2>/dev/null || echo "$p"
  else
    echo "$p"
  fi
}

build_images() {
  docker build -t pkilab/cmp-client "$(docker_path "${PROJECT_ROOT}/images/cmp-client")"
  docker build -t pkilab/tls-client "$(docker_path "${PROJECT_ROOT}/images/tls-client")"
  docker build -t pkilab/capture   "$(docker_path "${PROJECT_ROOT}/images/capture")"
  docker build -t pkilab/tls-server "$(docker_path "${PROJECT_ROOT}/images/tls-server")"
  docker build -f "$(docker_path "${PROJECT_ROOT}/images/analyzer/Dockerfile")" \
    -t pkilab/analyzer "$(docker_path "${PROJECT_ROOT}")"
}
