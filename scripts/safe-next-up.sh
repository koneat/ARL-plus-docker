#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_COMPOSE="docker-compose.yml"
NEXT_COMPOSE="docker-compose.next.yml"
BACKUP_ROOT="${ARL_NEXT_BACKUP_ROOT:-${HOME}/arl-next-backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"
GATEWAY_PORT="${NEXT_GATEWAY_PORT:-5173}"

log() {
  printf '[ARL Next Safe] %s\n' "$*"
}

fail() {
  printf '[ARL Next Safe][ERROR] %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "未找到 docker"
docker compose version >/dev/null 2>&1 || fail "必须使用 Docker Compose v2（docker compose）"

[[ -f "$BASE_COMPOSE" ]] || fail "缺少 ${BASE_COMPOSE}"
[[ -f "$NEXT_COMPOSE" ]] || fail "缺少 ${NEXT_COMPOSE}"
[[ -f "next/nginx.conf" ]] || fail "缺少 next/nginx.conf"

mkdir -p "$BACKUP_DIR"
for file in "$BASE_COMPOSE" "$NEXT_COMPOSE" "config-docker.yaml" ".env" "next/nginx.conf"; do
  if [[ -f "$file" ]]; then
    mkdir -p "${BACKUP_DIR}/$(dirname "$file")"
    cp -a "$file" "${BACKUP_DIR}/${file}"
  fi
done
log "配置已备份到 ${BACKUP_DIR}"

DC=(docker compose -f "$BASE_COMPOSE" -f "$NEXT_COMPOSE" --profile next)

log "校验 Compose 合并结果"
"${DC[@]}" config >/dev/null

running_services="$("${DC[@]}" ps --status running --services 2>/dev/null || true)"
for required in web mcp; do
  if ! grep -qx "$required" <<<"$running_services"; then
    fail "核心服务 ${required} 当前未运行。为避免影响现有环境，本脚本不会自动启动或重建核心服务。"
  fi
done

rollback_gateway() {
  log "只回滚 next-gateway，不操作 Web、Worker、MongoDB、RabbitMQ、MCP"
  "${DC[@]}" rm -sf next-gateway >/dev/null 2>&1 || true
}

trap 'log "启动失败，执行隔离回滚"; rollback_gateway' ERR

log "启动可选 next-gateway；使用 --no-deps，禁止重建核心服务"
"${DC[@]}" up -d --no-deps next-gateway

healthy=false
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${GATEWAY_PORT}/healthz" | grep -q '"status":"ok"'; then
    healthy=true
    break
  fi
  sleep 1
done

if [[ "$healthy" != "true" ]]; then
  "${DC[@]}" logs --tail=100 next-gateway || true
  fail "next-gateway 健康检查失败"
fi

trap - ERR
log "启动成功：http://127.0.0.1:${GATEWAY_PORT}"
log "现有 5003、5013、5014 和全部核心容器均未修改"
log "需要撤销时执行：bash scripts/safe-next-rollback.sh"
