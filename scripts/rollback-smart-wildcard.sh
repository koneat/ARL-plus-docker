#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${ARL_WILDCARD_BACKUP_ROOT:-/root/arl-smart-wildcard-backups}"
STATE_FILE="${1:-${BACKUP_ROOT}/latest.env}"

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
command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "需要 Docker Compose v2"

ROLLBACK_FILE="$(mktemp)"
trap 'rm -f "$ROLLBACK_FILE"' EXIT

if [[ -n "${BACKUP_TAG:-}" ]] && docker image inspect "$BACKUP_TAG" >/dev/null 2>&1; then
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
  log "已恢复到备份镜像：${BACKUP_TAG}"
else
  if [[ -n "${PROJECT_NAME:-}" ]]; then
    docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml \
      up -d --no-deps --force-recreate worker
  else
    docker compose -f docker-compose.yml \
      up -d --no-deps --force-recreate worker
  fi
  log "备份镜像不可用，已恢复 docker-compose.yml 中的基础 Worker"
fi

for _ in $(seq 1 20); do
  if [[ "$(docker inspect -f '{{.State.Status}}' "${WORKER_CONTAINER:-arl_worker}" 2>/dev/null || true)" == "running" ]]; then
    log "Worker 已运行；其他 ARL 容器未操作"
    exit 0
  fi
  sleep 2
done

docker logs --tail=120 "${WORKER_CONTAINER:-arl_worker}" || true
fail "回滚后 Worker 未进入 running 状态"
