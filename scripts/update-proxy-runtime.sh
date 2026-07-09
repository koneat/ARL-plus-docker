#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BACKUP_ROOT="${ARL_PROXY_BACKUP_ROOT:-/root/arl-proxy-runtime-backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"
STATE_FILE="${BACKUP_DIR}/state.env"
LATEST_FILE="${BACKUP_ROOT}/latest.env"
ENV_FILE="${ROOT_DIR}/.env"
ENV_TOOL="${ROOT_DIR}/scripts/compose-env.py"
RUNTIME_IMAGE="${ARL_PROXY_RUNTIME_IMAGE:-arl-proxy-runtime:v3.0.1-2026.07}"
BASE_IMAGE="${ARL_BASE_IMAGE:-ki9mu/arl-ki9mu:v3.0.1}"
WEB_CONTAINER="${ARL_WEB_CONTAINER:-arl_web}"
SCHEDULER_CONTAINER="${ARL_SCHEDULER_CONTAINER:-arl_scheduler}"
ROLLBACK_FILE="${BACKUP_DIR}/docker-compose.rollback.yml"
PROJECT_NAME=""
WEB_IMAGE_ID=""
SCHEDULER_IMAGE_ID=""
WEB_BACKUP_TAG=""
SCHEDULER_BACKUP_TAG=""
PREVIOUS_WEB_ENV_PRESENT=false
PREVIOUS_WEB_ENV_VALUE=""
PREVIOUS_SCHEDULER_ENV_PRESENT=false
PREVIOUS_SCHEDULER_ENV_VALUE=""
UPDATE_STARTED=false
UPDATE_SUCCEEDED=false

log() {
  printf '[ARL Proxy Runtime] %s\n' "$*"
}

fail() {
  printf '[ARL Proxy Runtime][ERROR] %s\n' "$*" >&2
  exit 1
}

state_value() {
  printf '%s=%q\n' "$1" "$2" >>"$STATE_FILE"
}

container_image() {
  docker inspect -f '{{.Image}}' "$1" 2>/dev/null || true
}

command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "需要 Docker Compose v2"
command -v python3 >/dev/null 2>&1 || fail "未找到 python3"
[[ -f docker-compose.yml ]] || fail "缺少 docker-compose.yml"
[[ -f docker-compose.proxy-runtime.yml ]] || fail "缺少 docker-compose.proxy-runtime.yml"
[[ -f proxy-runtime/Dockerfile ]] || fail "缺少 proxy-runtime/Dockerfile"
[[ -f "$ENV_TOOL" ]] || fail "缺少 scripts/compose-env.py"

mkdir -p "$BACKUP_DIR"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

if python3 "$ENV_TOOL" "$ENV_FILE" has ARL_WEB_IMAGE; then
  PREVIOUS_WEB_ENV_PRESENT=true
  PREVIOUS_WEB_ENV_VALUE="$(python3 "$ENV_TOOL" "$ENV_FILE" get ARL_WEB_IMAGE)"
fi
if python3 "$ENV_TOOL" "$ENV_FILE" has ARL_SCHEDULER_IMAGE; then
  PREVIOUS_SCHEDULER_ENV_PRESENT=true
  PREVIOUS_SCHEDULER_ENV_VALUE="$(python3 "$ENV_TOOL" "$ENV_FILE" get ARL_SCHEDULER_IMAGE)"
fi

WEB_IMAGE_ID="$(container_image "$WEB_CONTAINER")"
SCHEDULER_IMAGE_ID="$(container_image "$SCHEDULER_CONTAINER")"
if [[ -n "$WEB_IMAGE_ID" ]]; then
  PROJECT_NAME="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$WEB_CONTAINER" 2>/dev/null || true)"
  WEB_BACKUP_TAG="arl-web-backup:${STAMP}"
  docker image tag "$WEB_IMAGE_ID" "$WEB_BACKUP_TAG"
  log "当前 Web 镜像已备份：${WEB_BACKUP_TAG}"
fi
if [[ -n "$SCHEDULER_IMAGE_ID" ]]; then
  [[ -n "$PROJECT_NAME" ]] || PROJECT_NAME="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$SCHEDULER_CONTAINER" 2>/dev/null || true)"
  SCHEDULER_BACKUP_TAG="arl-scheduler-backup:${STAMP}"
  docker image tag "$SCHEDULER_IMAGE_ID" "$SCHEDULER_BACKUP_TAG"
  log "当前 Scheduler 镜像已备份：${SCHEDULER_BACKUP_TAG}"
fi

if [[ -n "$PROJECT_NAME" ]]; then
  COMPOSE=(docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml -f docker-compose.proxy-runtime.yml)
else
  COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.proxy-runtime.yml)
fi

: >"$STATE_FILE"
for pair in \
  "STAMP|$STAMP" \
  "ROOT_DIR|$ROOT_DIR" \
  "PROJECT_NAME|$PROJECT_NAME" \
  "WEB_CONTAINER|$WEB_CONTAINER" \
  "SCHEDULER_CONTAINER|$SCHEDULER_CONTAINER" \
  "WEB_IMAGE_ID|$WEB_IMAGE_ID" \
  "SCHEDULER_IMAGE_ID|$SCHEDULER_IMAGE_ID" \
  "WEB_BACKUP_TAG|$WEB_BACKUP_TAG" \
  "SCHEDULER_BACKUP_TAG|$SCHEDULER_BACKUP_TAG" \
  "RUNTIME_IMAGE|$RUNTIME_IMAGE" \
  "BASE_IMAGE|$BASE_IMAGE" \
  "ENV_FILE|$ENV_FILE" \
  "PREVIOUS_WEB_ENV_PRESENT|$PREVIOUS_WEB_ENV_PRESENT" \
  "PREVIOUS_WEB_ENV_VALUE|$PREVIOUS_WEB_ENV_VALUE" \
  "PREVIOUS_SCHEDULER_ENV_PRESENT|$PREVIOUS_SCHEDULER_ENV_PRESENT" \
  "PREVIOUS_SCHEDULER_ENV_VALUE|$PREVIOUS_SCHEDULER_ENV_VALUE"; do
  state_value "${pair%%|*}" "${pair#*|}"
done
cp -f "$STATE_FILE" "$LATEST_FILE"
chmod 600 "$STATE_FILE" "$LATEST_FILE"

restore_env_value() {
  local key="$1"
  local present="$2"
  local value="$3"
  if [[ "$present" == "true" ]]; then
    python3 "$ENV_TOOL" "$ENV_FILE" set "$key" "$value"
  else
    python3 "$ENV_TOOL" "$ENV_FILE" unset "$key"
  fi
}

rollback_services() {
  log "执行 Web/Scheduler 隔离回滚；不会操作 Worker、MongoDB、RabbitMQ 或 MCP"
  restore_env_value ARL_WEB_IMAGE "$PREVIOUS_WEB_ENV_PRESENT" "$PREVIOUS_WEB_ENV_VALUE"
  restore_env_value ARL_SCHEDULER_IMAGE "$PREVIOUS_SCHEDULER_ENV_PRESENT" "$PREVIOUS_SCHEDULER_ENV_VALUE"

  if [[ -n "$WEB_BACKUP_TAG" && -n "$SCHEDULER_BACKUP_TAG" ]] && \
     docker image inspect "$WEB_BACKUP_TAG" >/dev/null 2>&1 && \
     docker image inspect "$SCHEDULER_BACKUP_TAG" >/dev/null 2>&1; then
    cat >"$ROLLBACK_FILE" <<EOF
services:
  web:
    image: ${WEB_BACKUP_TAG}
  scheduler:
    image: ${SCHEDULER_BACKUP_TAG}
EOF
    if [[ -n "$PROJECT_NAME" ]]; then
      docker compose --project-name "$PROJECT_NAME" \
        -f docker-compose.yml -f "$ROLLBACK_FILE" \
        up -d --no-deps --force-recreate web scheduler || true
    else
      docker compose -f docker-compose.yml -f "$ROLLBACK_FILE" \
        up -d --no-deps --force-recreate web scheduler || true
    fi
  else
    if [[ -n "$PROJECT_NAME" ]]; then
      docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml \
        up -d --no-deps --force-recreate web scheduler || true
    else
      docker compose -f docker-compose.yml \
        up -d --no-deps --force-recreate web scheduler || true
    fi
  fi
}

cleanup_on_exit() {
  local status=$?
  if [[ $status -ne 0 && "$UPDATE_STARTED" == "true" && "$UPDATE_SUCCEEDED" != "true" ]]; then
    rollback_services
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT

log "校验 Compose 合并结果"
ARL_BASE_IMAGE="$BASE_IMAGE" ARL_PROXY_RUNTIME_IMAGE="$RUNTIME_IMAGE" \
  "${COMPOSE[@]}" config >/dev/null

log "构建持久化 PySocks 运行时：${RUNTIME_IMAGE}"
ARL_BASE_IMAGE="$BASE_IMAGE" ARL_PROXY_RUNTIME_IMAGE="$RUNTIME_IMAGE" \
  "${COMPOSE[@]}" build --pull web scheduler

docker run --rm --entrypoint python3.6 "$RUNTIME_IMAGE" \
  -c 'import socks; print("proxy-runtime-import-ok")'

UPDATE_STARTED=true
python3 "$ENV_TOOL" "$ENV_FILE" set ARL_WEB_IMAGE "$RUNTIME_IMAGE"
python3 "$ENV_TOOL" "$ENV_FILE" set ARL_SCHEDULER_IMAGE "$RUNTIME_IMAGE"

log "仅重建 Web 与 Scheduler；Worker、MongoDB、RabbitMQ 和 MCP 不受影响"
ARL_BASE_IMAGE="$BASE_IMAGE" ARL_PROXY_RUNTIME_IMAGE="$RUNTIME_IMAGE" \
  "${COMPOSE[@]}" up -d --no-deps --force-recreate web scheduler

healthy=false
for _ in $(seq 1 50); do
  web_state="$(docker inspect -f '{{.State.Status}}' "$WEB_CONTAINER" 2>/dev/null || true)"
  scheduler_state="$(docker inspect -f '{{.State.Status}}' "$SCHEDULER_CONTAINER" 2>/dev/null || true)"
  if [[ "$web_state" == "running" && "$scheduler_state" == "running" ]] && \
     docker exec "$WEB_CONTAINER" python3.6 -c 'import socks' >/dev/null 2>&1 && \
     docker exec "$SCHEDULER_CONTAINER" python3.6 -c 'import socks' >/dev/null 2>&1 && \
     curl -kfsS --connect-timeout 3 --max-time 8 \
       "https://127.0.0.1:${ARL_HTTPS_PORT:-5003}/api/doc" >/dev/null 2>&1 && \
     docker exec "$SCHEDULER_CONTAINER" sh -c \
       "ps -ef | grep -v grep | grep -q 'python3.6 -m app.scheduler'"; then
    healthy=true
    break
  fi
  sleep 3
done

if [[ "$healthy" != "true" ]]; then
  docker logs --tail=160 "$WEB_CONTAINER" || true
  docker logs --tail=160 "$SCHEDULER_CONTAINER" || true
  fail "Web/Scheduler 持久化代理运行时未通过启动检查"
fi

UPDATE_SUCCEEDED=true
trap - EXIT
log "更新完成：Web 与 Scheduler 已使用 ${RUNTIME_IMAGE}"
log "镜像选择已持久化到 ${ENV_FILE}"
log "回滚状态文件：${STATE_FILE}"
log "手工回滚命令：bash scripts/rollback-proxy-runtime.sh"
