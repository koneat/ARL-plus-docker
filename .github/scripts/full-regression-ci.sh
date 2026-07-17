#!/usr/bin/env bash
set -Eeuo pipefail

mode="${1:?mode required}"

# GitHub Actions 日志容量有限。正式镜像仍从零完整构建，但仅输出最终镜像 ID，
# 将日志预算留给实际启动、扫描、报告和鉴权错误。
docker() {
  if [[ "${1:-}" == "build" ]]; then
    shift
    command docker build --quiet "$@"
    return
  fi
  if [[ "${1:-}" == "compose" && "${2:-}" == "build" ]]; then
    shift 2
    command docker compose build --quiet "$@"
    return
  fi
  command docker "$@"
}
export -f docker

exec bash .github/scripts/full-regression.sh "$mode"
