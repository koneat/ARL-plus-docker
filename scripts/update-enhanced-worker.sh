#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BACKUP_ROOT="${ARL_ENHANCED_BACKUP_ROOT:-/root/arl-enhanced-worker-backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"
STATE_FILE="${BACKUP_DIR}/state.env"
LATEST_FILE="${BACKUP_ROOT}/latest.env"
ENV_FILE="${ROOT_DIR}/.env"
ENV_TOOL="${ROOT_DIR}/scripts/compose-env.py"
ENHANCED_IMAGE="${ARL_ENHANCED_WORKER_IMAGE:-arl-enhanced-worker:v3.0.1-2026.07}"
BASE_IMAGE="${ARL_BASE_IMAGE:-ki9mu/arl-ki9mu:v3.0.1}"
MERGE_FULL_DOMAIN="${ARL_MERGE_FULL_DOMAIN_WORDLIST:-false}"
WORKER_CONTAINER="${ARL_WORKER_CONTAINER:-arl_worker}"
ROLLBACK_FILE="${BACKUP_DIR}/docker-compose.rollback.yml"
PROJECT_NAME=""
CURRENT_IMAGE_ID=""
BACKUP_TAG=""
PREVIOUS_ENV_PRESENT=false
PREVIOUS_ENV_VALUE=""
UPDATE_STARTED=false
UPDATE_SUCCEEDED=false

log() {
  printf '[ARL Enhanced Worker] %s\n' "$*"
}

fail() {
  printf '[ARL Enhanced Worker][ERROR] %s\n' "$*" >&2
  exit 1
}

state_value() {
  local key="$1"
  local value="$2"
  printf '%s=%q\n' "$key" "$value" >>"$STATE_FILE"
}

command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "需要 Docker Compose v2（docker compose）"
command -v python3 >/dev/null 2>&1 || fail "未找到 python3"
[[ -f docker-compose.yml ]] || fail "缺少 docker-compose.yml"
[[ -f docker-compose.enhanced-worker.yml ]] || fail "缺少 docker-compose.enhanced-worker.yml"
[[ -f enhanced-worker/Dockerfile ]] || fail "缺少 enhanced-worker/Dockerfile"
[[ -f enhanced-worker/afrog_scan.py ]] || fail "缺少 enhanced-worker/afrog_scan.py"
[[ -f "$ENV_TOOL" ]] || fail "缺少 scripts/compose-env.py"
for wordlist in \
  wordlists/vendor/api-endpoints.txt \
  wordlists/vendor/raft-small-files.txt \
  wordlists/vendor/subdomains-main.txt \
  wordlists/vendor/SOURCES.env; do
  [[ -s "$wordlist" ]] || fail "仓库内置字典缺失或为空：$wordlist"
done

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
  COMPOSE=(docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml -f docker-compose.enhanced-worker.yml)
  BASE_COMPOSE=(docker compose --project-name "$PROJECT_NAME" -f docker-compose.yml)
else
  COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.enhanced-worker.yml)
  BASE_COMPOSE=(docker compose -f docker-compose.yml)
fi

: >"$STATE_FILE"
state_value STAMP "$STAMP"
state_value ROOT_DIR "$ROOT_DIR"
state_value PROJECT_NAME "$PROJECT_NAME"
state_value WORKER_CONTAINER "$WORKER_CONTAINER"
state_value CURRENT_IMAGE_ID "$CURRENT_IMAGE_ID"
state_value BACKUP_TAG "$BACKUP_TAG"
state_value ENHANCED_IMAGE "$ENHANCED_IMAGE"
state_value BASE_IMAGE "$BASE_IMAGE"
state_value MERGE_FULL_DOMAIN "$MERGE_FULL_DOMAIN"
state_value ENV_FILE "$ENV_FILE"
state_value PREVIOUS_ENV_PRESENT "$PREVIOUS_ENV_PRESENT"
state_value PREVIOUS_ENV_VALUE "$PREVIOUS_ENV_VALUE"
cp -f "$STATE_FILE" "$LATEST_FILE"
chmod 600 "$STATE_FILE" "$LATEST_FILE"

rollback_worker() {
  log "执行 Worker 隔离回滚；不会操作 Web、Scheduler、MongoDB、RabbitMQ 或 MCP"
  if [[ -n "$BACKUP_TAG" ]] && docker image inspect "$BACKUP_TAG" >/dev/null 2>&1; then
    python3 "$ENV_TOOL" "$ENV_FILE" set ARL_WORKER_IMAGE "$BACKUP_TAG"
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
    if [[ "$PREVIOUS_ENV_PRESENT" == "true" ]]; then
      python3 "$ENV_TOOL" "$ENV_FILE" set ARL_WORKER_IMAGE "$PREVIOUS_ENV_VALUE"
    else
      python3 "$ENV_TOOL" "$ENV_FILE" unset ARL_WORKER_IMAGE
    fi
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
ARL_BASE_IMAGE="$BASE_IMAGE" \
ARL_ENHANCED_WORKER_IMAGE="$ENHANCED_IMAGE" \
ARL_MERGE_FULL_DOMAIN_WORDLIST="$MERGE_FULL_DOMAIN" \
  "${COMPOSE[@]}" config >/dev/null

log "构建持久化增强 Worker 镜像：${ENHANCED_IMAGE}"
ARL_BASE_IMAGE="$BASE_IMAGE" \
ARL_ENHANCED_WORKER_IMAGE="$ENHANCED_IMAGE" \
ARL_MERGE_FULL_DOMAIN_WORDLIST="$MERGE_FULL_DOMAIN" \
  "${COMPOSE[@]}" build --pull worker

log "执行镜像离线自检"
docker run --rm --entrypoint sh "$ENHANCED_IMAGE" -c '
  set -e
  check() {
    "$@" || {
      echo "[SELF-CHECK][FAIL] $*" >&2
      exit 1
    }
  }
  python3.6 -m py_compile \
    /code/app/services/massdns.py \
    /code/app/services/wildcardSmart.py \
    /code/app/services/nuclei_scan.py \
    /code/app/services/afrog_scan.py \
    /code/app/services/commonTask.py \
    /code/app/tasks/domain.py
  python3.6 -c "import socks; from app.services.wildcardSmart import WildcardSmartFilter; from app.services.nuclei_scan import NucleiScan; from app.services.afrog_scan import AfrogTaskScan; from app.services.commonTask import WebSiteFetch; print(\"enhanced-worker-import-ok\")"
  check command -v nuclei
  check command -v afrog
  check command -v rad
  check command -v afrog-arl
  check test -e /usr/lib64/libpcap.so.0.8
  check test -s /opt/arl-wordlists/api-endpoints.txt
  check test -s /opt/arl-wordlists/raft-small-files.txt
  check test -s /opt/arl-wordlists/subdomains-main.txt
  check grep -qx "api/auth/login" /opt/arl-wordlists/api-endpoints.txt
  check grep -qx "index.php" /opt/arl-wordlists/raft-small-files.txt
  check grep -qx "admin" /opt/arl-wordlists/subdomains-main.txt
  check grep -qx ".env" /code/app/dicts/file_top_2000.txt
  check grep -qx "swagger.json" /code/app/dicts/file_top_2000.txt
  check grep -qx "admin" /code/app/dicts/domain_2w.txt
  check grep -q "ARL_NUCLEI_TAGS" /code/app/services/nuclei_scan.py
  check grep -q "executed_zero_findings" /code/app/services/afrog_scan.py
  check grep -q "def afrog_scan(self):" /code/app/services/commonTask.py
  check grep -q "self.run_func(\"afrog_scan\", self.afrog_scan)" /code/app/services/commonTask.py
  check grep -q "update_services" /code/app/services/commonTask.py
  check grep -q "WildcardSmartFilter" /code/app/tasks/domain.py
  ! grep -q "if ip in self.not_found_domain_ips" /code/app/tasks/domain.py
'

UPDATE_STARTED=true
python3 "$ENV_TOOL" "$ENV_FILE" set ARL_WORKER_IMAGE "$ENHANCED_IMAGE"
python3 "$ENV_TOOL" "$ENV_FILE" set ARL_MERGE_FULL_DOMAIN_WORDLIST "$MERGE_FULL_DOMAIN"

log "仅重建 arl_worker；不重启其他容器"
ARL_BASE_IMAGE="$BASE_IMAGE" \
ARL_ENHANCED_WORKER_IMAGE="$ENHANCED_IMAGE" \
ARL_MERGE_FULL_DOMAIN_WORDLIST="$MERGE_FULL_DOMAIN" \
  "${COMPOSE[@]}" up -d --no-deps --force-recreate worker

log "检查 Worker 进程、工具、字典和任务补丁加载状态"
healthy=false
for _ in $(seq 1 40); do
  state="$(docker inspect -f '{{.State.Status}}' "$WORKER_CONTAINER" 2>/dev/null || true)"
  if [[ "$state" == "running" ]] && \
     docker exec "$WORKER_CONTAINER" sh -c \
       "python3.6 -c 'import socks; from app.services.wildcardSmart import WildcardSmartFilter; from app.services.nuclei_scan import NucleiScan; from app.services.afrog_scan import AfrogTaskScan; from app.services.commonTask import WebSiteFetch; import app.tasks.domain'" >/dev/null 2>&1 && \
     docker exec "$WORKER_CONTAINER" sh -c \
       "command -v nuclei && command -v afrog && command -v rad && test -e /usr/lib64/libpcap.so.0.8 && test -s /opt/arl-wordlists/subdomains-main.txt && grep -qx '.env' /code/app/dicts/file_top_2000.txt && grep -qx 'swagger.json' /code/app/dicts/file_top_2000.txt && grep -q 'def afrog_scan(self):' /code/app/services/commonTask.py" >/dev/null 2>&1 && \
     docker exec "$WORKER_CONTAINER" sh -c \
       "ps -ef | grep -v grep | grep -q 'celery -A app.celerytask.celery worker'"; then
    healthy=true
    break
  fi
  sleep 3
done

if [[ "$healthy" != "true" ]]; then
  docker logs --tail=200 "$WORKER_CONTAINER" || true
  fail "持久化增强 Worker 未通过启动检查"
fi

recent_logs="$(docker logs --since 120s "$WORKER_CONTAINER" 2>&1 || true)"
if grep -Eiq '(^|[^a-z])(Traceback|SyntaxError|ImportError|ModuleNotFoundError)([^a-z]|$)' <<<"$recent_logs"; then
  printf '%s\n' "$recent_logs" >&2
  fail "Worker 新日志中发现 Python 启动异常"
fi

UPDATE_SUCCEEDED=true
trap - EXIT
log "更新完成：${WORKER_CONTAINER} 已切换到 ${ENHANCED_IMAGE}"
log "镜像选择已持久化到 ${ENV_FILE} 的 ARL_WORKER_IMAGE"
log "ARL 站点任务已挂载自动 Afrog；Afrog 通过 ARL_XRAY_PROXY_URL 进入长亭 xray"
log "状态报告：${ARL_REPORT_ROOT:-/var/lib/arl-reports}/afrog/*.status.json"
log "仓库内置字典已写入镜像 /opt/arl-wordlists"
log "回滚状态文件：${STATE_FILE}"
log "手工回滚命令：bash scripts/rollback-enhanced-worker.sh"
