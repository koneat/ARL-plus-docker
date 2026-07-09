#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${ARL_PROXY_BACKUP_ROOT:-/root/arl-proxy-runtime-backups}"
STATE_FILE="${1:-${BACKUP_ROOT}/latest.env}"
ENV_TOOL="${ROOT_DIR}/scripts/compose-env.py"

log() {
  printf '[ARL Proxy Runtime Rollback] %s\n' "$*"
}

fail() {
  printf '[ARL Proxy Runtime Rollback][ERROR] %s\n' "$*" >&2
  exit 1
}

[[ -f "$STATE_FILE" ]] || fail "找不到回滚状态文件：${STATE_FILE}"
# shellcheck disable=SC1090
source "$STATE_FILE"
cd "${ROOT_DIR:-$PWD}"

[[ -f docker-compose.yml ]] || fail "缺少 docker-compose.yml"
[[ -f "$ENV_TOOL" ]] || fail "缺少 scripts/compose-env.py"
command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "需要 Docker Compose v2"

env_file="${ENV_FILE:-${ROOT_DIR}/.env}"
touch "$env_file"
chmod 600 "$env_file"
rollback_file="$(mktemp)"
trap 'rm -f "$rollback_file"' EXIT

restore_env_value() {
  local key="$1"
  local present="$2"
  local value="$3"
  if [[ "$present" == "true" ]]; then
    python3 "$ENV_TOOL" "$env_file" set "$key" "$value"
  else
    python3 "$ENV_TOOL" "$env_file" unset "$key"
  fi
}

restore_env_value ARL_WEB_IMAGE "${PREVIOUS_WEB_ENV_PRESENT:-false}" "${PREVIOUS_WEB_ENV_VALUE:-}"
restore_env_value ARL_SCHEDULER_IMAGE "${PREVIOUS_SCHEDULER_ENV_PRESENT:-false}" "${PREVIOUS_SCHEDULER_ENV_VALUE:-}"

if [[ -n "${WEB_BACKUP_TAG:-}" && -n "${SCHEDULER_BACKUP_TAG:-}" ]] && \
   docker image inspect "$WEB_BACKUP_TAG" >/dev/null 2>&1 && \
   docker image inspect "$SCHEDULER_BACKUP_TAG" >/dev/null 2>&1; then
  cat >"$rollback_file" <<EOF
services:
  web:
    image: ${WEB_BACKUP_TAG}
  scheduler:
    image: ${SCHEDULER_BACKUP_TAG}
EOF
  if [[ -n "${PROJECT_NAME:-}" ]]; then
    docker compose --project-name "$PROJECT_NAME" \
      -f docker-compose.yml -f "$rollback_file" \
      up -d --no-deps --force-recreate web scheduler
  else
    docker compose -f docker-compose.yml -f "$rollback_file" \
      up -d --no-deps --force-recreate web scheduler
  fi
  log "已恢复到 Web/Scheduler 精确备份镜像"
else
  if [[ -n "${PROJECT_NAME:-}" ]]; then
    docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml \
      up -d --no-deps --force-recreate web scheduler
  else
    docker compose -f docker-compose.yml \
      up -d --no-deps --force-recreate web scheduler
  fi
  log "精确备份镜像不可用，已恢复更新前的 Compose 镜像配置"
fi

for _ in $(seq 1 40); do
  web_state="$(docker inspect -f '{{.State.Status}}' "${WEB_CONTAINER:-arl_web}" 2>/dev/null || true)"
  scheduler_state="$(docker inspect -f '{{.State.Status}}' "${SCHEDULER_CONTAINER:-arl_scheduler}" 2>/dev/null || true)"
  if [[ "$web_state" == "running" && "$scheduler_state" == "running" ]] && \
     curl -kfsS --connect-timeout 3 --max-time 8 \
       "https://127.0.0.1:${ARL_HTTPS_PORT:-5003}/api/doc" >/dev/null 2>&1 && \
     docker exec "${SCHEDULER_CONTAINER:-arl_scheduler}" sh -c \
       "ps -ef | grep -v grep | grep -q 'python3.6 -m app.scheduler'"; then
    log "Web 与 Scheduler 已恢复运行；其他容器未操作"
    exit 0
  fi
  sleep 3
done

docker logs --tail=160 "${WEB_CONTAINER:-arl_web}" || true
docker logs --tail=160 "${SCHEDULER_CONTAINER:-arl_scheduler}" || true
fail "回滚后 Web/Scheduler 未通过运行检查"
