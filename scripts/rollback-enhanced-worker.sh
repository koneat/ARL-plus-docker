#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${ARL_ENHANCED_BACKUP_ROOT:-/root/arl-enhanced-worker-backups}"
STATE_FILE="${1:-${BACKUP_ROOT}/latest.env}"
ENV_TOOL="${ROOT_DIR}/scripts/compose-env.py"

log() {
  printf '[ARL Enhanced Worker Rollback] %s\n' "$*"
}

fail() {
  printf '[ARL Enhanced Worker Rollback][ERROR] %s\n' "$*" >&2
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

touch "${ENV_FILE:-${ROOT_DIR}/.env}"
chmod 600 "${ENV_FILE:-${ROOT_DIR}/.env}"
ROLLBACK_FILE="$(mktemp)"
trap 'rm -f "$ROLLBACK_FILE"' EXIT

if [[ -n "${BACKUP_TAG:-}" ]] && docker image inspect "$BACKUP_TAG" >/dev/null 2>&1; then
  python3 "$ENV_TOOL" "${ENV_FILE:-${ROOT_DIR}/.env}" set ARL_WORKER_IMAGE "$BACKUP_TAG"
  cat >"$ROLLBACK_FILE" <<EOF
services:
  worker:
    image: ${BACKUP_TAG}
EOF
  if [[ -n "${PROJECT_NAME:-}" ]]; then
    docker compose --project-name "$PROJECT_NAME" \
      -f docker-compose.yml -f "$ROLLBACK_FILE" \
      up -d --no-deps --force-recreate worker
  else
    docker compose -f docker-compose.yml -f "$ROLLBACK_FILE" \
      up -d --no-deps --force-recreate worker
  fi
  log "已恢复到精确备份镜像：${BACKUP_TAG}"
else
  if [[ "${PREVIOUS_ENV_PRESENT:-false}" == "true" ]]; then
    python3 "$ENV_TOOL" "${ENV_FILE:-${ROOT_DIR}/.env}" set ARL_WORKER_IMAGE "${PREVIOUS_ENV_VALUE:-}"
  else
    python3 "$ENV_TOOL" "${ENV_FILE:-${ROOT_DIR}/.env}" unset ARL_WORKER_IMAGE
  fi
  if [[ -n "${PROJECT_NAME:-}" ]]; then
    docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml \
      up -d --no-deps --force-recreate worker
  else
    docker compose -f docker-compose.yml \
      up -d --no-deps --force-recreate worker
  fi
  log "精确备份镜像不可用，已恢复更新前的 Compose 镜像配置"
fi

for _ in $(seq 1 30); do
  if [[ "$(docker inspect -f '{{.State.Status}}' "${WORKER_CONTAINER:-arl_worker}" 2>/dev/null || true)" == "running" ]] && \
     docker exec "${WORKER_CONTAINER:-arl_worker}" sh -c \
       "ps -ef | grep -v grep | grep -q 'celery -A app.celerytask.celery worker'"; then
    log "Worker 已恢复运行；其他 ARL 容器未操作"
    exit 0
  fi
  sleep 2
done

docker logs --tail=160 "${WORKER_CONTAINER:-arl_worker}" || true
fail "回滚后 Worker 未通过运行检查"
