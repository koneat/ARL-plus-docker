#!/usr/bin/env bash
set -Eeuo pipefail

mode="${1:?mode required}"
runner='.github/scripts/.full-regression-ci-run.sh'

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

# 原回归脚本退出时会立即删除容器，导致 Actions 的失败诊断看不到现场。
# CI 副本只移除 EXIT 清理 trap；工作流的 always() 步骤统一负责最终清理。
python3 - .github/scripts/full-regression.sh "$runner" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding='utf-8')
lines = []
for line in source.splitlines():
    stripped = line.strip()
    if stripped == 'trap cleanup_runtime EXIT':
        continue
    if stripped.startswith("trap 'docker compose down -v --remove-orphans"):
        continue
    lines.append(line)
Path(sys.argv[2]).write_text('\n'.join(lines) + '\n', encoding='utf-8')
PY
chmod 0700 "$runner"

exec bash "$runner" "$mode"
