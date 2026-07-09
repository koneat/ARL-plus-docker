#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BACKUP_ROOT="${ARL_WILDCARD_BACKUP_ROOT:-/root/arl-smart-wildcard-backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"
STATE_FILE="${BACKUP_DIR}/state.env"
LATEST_FILE="${BACKUP_ROOT}/latest.env"
SMART_IMAGE="${ARL_SMART_WORKER_IMAGE:-arl-smart-wildcard:v3.0.1}"
BASE_IMAGE="${ARL_BASE_IMAGE:-ki9mu/arl-ki9mu:v3.0.1}"
WORKER_CONTAINER="${ARL_WORKER_CONTAINER:-arl_worker}"
ROLLBACK_FILE="${BACKUP_DIR}/docker-compose.rollback.yml"
ENV_FILE="${ROOT_DIR}/.env"
ENV_TOOL="${ROOT_DIR}/scripts/compose-env.py"
PROJECT_NAME=""
CURRENT_IMAGE_ID=""
BACKUP_TAG=""
PREVIOUS_ENV_PRESENT=false
PREVIOUS_ENV_VALUE=""
UPDATE_STARTED=false
UPDATE_SUCCEEDED=false

log() {
  printf '[ARL Smart Wildcard] %s\n' "$*"
}

fail() {
  printf '[ARL Smart Wildcard][ERROR] %s\n' "$*" >&2
  exit 1
}

state_value() {
  printf '%s=%q\n' "$1" "$2" >>"$STATE_FILE"
}

command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "需要 Docker Compose v2（docker compose）"
command -v python3 >/dev/null 2>&1 || fail "未找到 python3"
[[ -f docker-compose.yml ]] || fail "缺少 docker-compose.yml"
[[ -f docker-compose.smart-wildcard.yml ]] || fail "缺少 docker-compose.smart-wildcard.yml"
[[ -f smart-worker/Dockerfile ]] || fail "缺少 smart-worker/Dockerfile"
[[ -f "$ENV_TOOL" ]] || fail "缺少 scripts/compose-env.py"

mkdir -p "$BACKUP_DIR"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

if python3 "$ENV_TOOL" "$ENV_FILE" has ARL_WORKER_IMAGE; then
  PREVIOUS_ENV_PRESENT=true
  PREVIOUS_ENV_VALUE="$(python3 "$ENV_TOOL" "$ENV_FILE" get ARL_WORKER_IMAGE)"
fi

if docker inspect "$WORKER_CONTAINER" >/dev/null 2>&1; then
  CURRENT_IMAGE_ID="$(docker inspect -f '{{.Image}}' "$WORKER_CONTAINER")"
  PROJECT_NAME="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$WORKER_CONTAINER" 2>/dev/null || true)"
  BACKUP_TAG="arl-worker-backup:${STAMP}"
  docker image tag "$CURRENT_IMAGE_ID" "$BACKUP_TAG"
  log "当前 Worker 镜像已备份：${BACKUP_TAG} (${CURRENT_IMAGE_ID})"
else
  log "未发现现有 ${WORKER_CONTAINER}；失败时恢复 Compose 默认 Worker"
fi

if [[ -n "$PROJECT_NAME" ]]; then
  COMPOSE=(docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml -f docker-compose.smart-wildcard.yml)
  BASE_COMPOSE=(docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml)
else
  COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.smart-wildcard.yml)
  BASE_COMPOSE=(docker compose -f docker-compose.yml)
fi

: >"$STATE_FILE"
state_value STAMP "$STAMP"
state_value ROOT_DIR "$ROOT_DIR"
state_value PROJECT_NAME "$PROJECT_NAME"
state_value WORKER_CONTAINER "$WORKER_CONTAINER"
state_value CURRENT_IMAGE_ID "$CURRENT_IMAGE_ID"
state_value BACKUP_TAG "$BACKUP_TAG"
state_value SMART_IMAGE "$SMART_IMAGE"
state_value BASE_IMAGE "$BASE_IMAGE"
state_value ENV_FILE "$ENV_FILE"
state_value PREVIOUS_ENV_PRESENT "$PREVIOUS_ENV_PRESENT"
state_value PREVIOUS_ENV_VALUE "$PREVIOUS_ENV_VALUE"
cp -f "$STATE_FILE" "$LATEST_FILE"
chmod 600 "$STATE_FILE" "$LATEST_FILE"

restore_previous_env() {
  if [[ "$PREVIOUS_ENV_PRESENT" == "true" ]]; then
    python3 "$ENV_TOOL" "$ENV_FILE" set ARL_WORKER_IMAGE "$PREVIOUS_ENV_VALUE"
  else
    python3 "$ENV_TOOL" "$ENV_FILE" unset ARL_WORKER_IMAGE
  fi
}

rollback_worker() {
  log "执行 Worker 隔离回滚；不会操作 Web、Scheduler、MongoDB、RabbitMQ 或 MCP"
  restore_previous_env
  if [[ -n "$BACKUP_TAG" ]] && docker image inspect "$BACKUP_TAG" >/dev/null 2>&1; then
    cat >"$ROLLBACK_FILE" <<EOF
services:
  worker:
    image: ${BACKUP_TAG}
EOF
    if [[ -n "$PROJECT_NAME" ]]; then
      docker compose --project-name "$PROJECT_NAME" \
        -f docker-compose.yml -f "$ROLLBACK_FILE" \
        up -d --no-deps --force-recreate worker || true
    else
      docker compose -f docker-compose.yml -f "$ROLLBACK_FILE" \
        up -d --no-deps --force-recreate worker || true
    fi
  else
    "${BASE_COMPOSE[@]}" up -d --no-deps --force-recreate worker || true
  fi
}

cleanup_on_exit() {
  local status=$?
  if [[ $status -ne 0 && "$UPDATE_STARTED" == "true" && "$UPDATE_SUCCEEDED" != "true" ]]; then
    rollback_worker
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT

log "校验 Compose 合并结果"
ARL_BASE_IMAGE="$BASE_IMAGE" ARL_SMART_WORKER_IMAGE="$SMART_IMAGE" \
  "${COMPOSE[@]}" config >/dev/null

log "构建智能泛解析 Worker 镜像：${SMART_IMAGE}"
ARL_BASE_IMAGE="$BASE_IMAGE" ARL_SMART_WORKER_IMAGE="$SMART_IMAGE" \
  "${COMPOSE[@]}" build --pull worker

log "执行镜像离线自检"
docker run --rm --entrypoint sh "$SMART_IMAGE" -c '
  set -e
  python3.6 -m py_compile \
    /code/app/services/massdns.py \
    /code/app/services/wildcardSmart.py \
    /code/app/tasks/domain.py
  grep -q "WildcardSmartFilter" /code/app/tasks/domain.py
  ! grep -q "if ip in self.not_found_domain_ips" /code/app/tasks/domain.py
  python3.6 -c "from app.services.wildcardSmart import WildcardSmartFilter; print(\"wildcard-smart-import-ok\")"
'

UPDATE_STARTED=true
python3 "$ENV_TOOL" "$ENV_FILE" set ARL_WORKER_IMAGE "$SMART_IMAGE"

log "仅重建 arl_worker；不重启其他容器"
ARL_BASE_IMAGE="$BASE_IMAGE" ARL_SMART_WORKER_IMAGE="$SMART_IMAGE" \
  "${COMPOSE[@]}" up -d --no-deps --force-recreate worker

log "检查 Worker 进程和补丁加载状态"
healthy=false
for _ in $(seq 1 30); do
  state="$(docker inspect -f '{{.State.Status}}' "$WORKER_CONTAINER" 2>/dev/null || true)"
  if [[ "$state" == "running" ]] && \
     docker exec "$WORKER_CONTAINER" sh -c \
       "python3.6 -c 'from app.services.wildcardSmart import WildcardSmartFilter; import app.tasks.domain'" >/dev/null 2>&1 && \
     docker exec "$WORKER_CONTAINER" sh -c \
       "ps -ef | grep -v grep | grep -q 'celery -A app.celerytask.celery worker'"; then
    healthy=true
    break
  fi
  sleep 2
done

if [[ "$healthy" != "true" ]]; then
  docker logs --tail=160 "$WORKER_CONTAINER" || true
  fail "智能 Worker 未通过启动检查"
fi

recent_logs="$(docker logs --since 90s "$WORKER_CONTAINER" 2>&1 || true)"
if grep -Eiq '(^|[^a-z])(Traceback|SyntaxError|ImportError|ModuleNotFoundError)([^a-z]|$)' <<<"$recent_logs"; then
  printf '%s\n' "$recent_logs" >&2
  fail "Worker 新日志中发现 Python 启动异常"
fi

UPDATE_SUCCEEDED=true
trap - EXIT
log "更新完成：仅 ${WORKER_CONTAINER} 已切换到 ${SMART_IMAGE}"
log "镜像选择已持久化到 ${ENV_FILE} 的 ARL_WORKER_IMAGE"
log "回滚状态文件：${STATE_FILE}"
log "手工回滚命令：bash scripts/rollback-smart-wildcard.sh"
