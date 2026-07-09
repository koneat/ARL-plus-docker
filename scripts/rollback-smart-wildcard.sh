#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${ARL_WILDCARD_BACKUP_ROOT:-/root/arl-smart-wildcard-backups}"
STATE_FILE="${1:-${BACKUP_ROOT}/latest.env}"
ENV_TOOL="${ROOT_DIR}/scripts/compose-env.py"

log() {
  printf '[ARL Smart Wildcard Rollback] %s\n' "$*"
}

fail() {
  printf '[ARL Smart Wildcard Rollback][ERROR] %s\n' "$*" >&2
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

if [[ "${PREVIOUS_ENV_PRESENT:-false}" == "true" ]]; then
  python3 "$ENV_TOOL" "$env_file" set ARL_WORKER_IMAGE "${PREVIOUS_ENV_VALUE:-}"
else
  python3 "$ENV_TOOL" "$env_file" unset ARL_WORKER_IMAGE
fi

if [[ -n "${BACKUP_TAG:-}" ]] && docker image inspect "$BACKUP_TAG" >/dev/null 2>&1; then
  cat >"$rollback_file" <<EOF
services:
  worker:
    image: ${BACKUP_TAG}
EOF
  if [[ -n "${PROJECT_NAME:-}" ]]; then
    docker compose --project-name "$PROJECT_NAME" \
      -f docker-compose.yml -f "$rollback_file" \
      up -d --no-deps --force-recreate worker
  else
    docker compose -f docker-compose.yml -f "$rollback_file" \
      up -d --no-deps --force-recreate worker
  fi
  log "已恢复到精确备份镜像：${BACKUP_TAG}"
else
  if [[ -n "${PROJECT_NAME:-}" ]]; then
    docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml \
      up -d --no-deps --force-recreate worker
  else
    docker compose -f docker-compose.yml \
      up -d --no-deps --force-recreate worker
  fi
  log "精确备份镜像不可用，已恢复更新前的 Compose Worker 配置"
fi

for _ in $(seq 1 30); do
  if [[ "$(docker inspect -f '{{.State.Status}}' "${WORKER_CONTAINER:-arl_worker}" 2>/dev/null || true)" == "running" ]] && \
     docker exec "${WORKER_CONTAINER:-arl_worker}" sh -c \
       "ps -ef | grep -v grep | grep -q 'celery -A app.celerytask.celery worker'"; then
    log "Worker 已运行；其他 ARL 容器未操作"
    exit 0
  fi
  sleep 2
done

docker logs --tail=120 "${WORKER_CONTAINER:-arl_worker}" || true
fail "回滚后 Worker 未通过运行检查"
