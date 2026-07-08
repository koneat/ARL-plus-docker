#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v docker >/dev/null 2>&1 || {
  echo '[ARL Next Safe][ERROR] 未找到 docker' >&2
  exit 1
}

docker compose version >/dev/null 2>&1 || {
  echo '[ARL Next Safe][ERROR] 必须使用 Docker Compose v2（docker compose）' >&2
  exit 1
}

DC=(docker compose -f docker-compose.yml -f docker-compose.next.yml --profile next)

# 只删除新增的可选网关容器；不执行 down，不删除卷，不触碰任何核心服务。
"${DC[@]}" rm -sf next-gateway || true

echo '[ARL Next Safe] next-gateway 已撤销。'
echo '[ARL Next Safe] Web、Worker、Scheduler、MongoDB、RabbitMQ、MCP 和数据卷均未修改。'
