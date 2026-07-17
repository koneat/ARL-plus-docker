#!/usr/bin/env bash
set -Eeuo pipefail

mode="${1:?mode required}"
runner='.github/scripts/.full-regression-ci-run.sh'

# GitHub Actions 日志容量有限。正式镜像由 build-images 作业从零构建一次；
# 两个运行测试加载完全相同的镜像，避免重复编译造成无意义等待。
docker() {
  if [[ "${1:-}" == "build" ]]; then
    if [[ "${REGRESSION_IMAGES_PREBUILT:-false}" == true ]]; then
      command docker image inspect arl-e2e-scanner-image >/dev/null
      command docker image inspect arl-e2e-mcp-image >/dev/null
      return
    fi
    shift
    command docker build --quiet "$@"
    return
  fi
  if [[ "${1:-}" == "compose" && "${2:-}" == "build" ]]; then
    if [[ "${REGRESSION_IMAGES_PREBUILT:-false}" == true ]]; then
      command docker image inspect arl-plus-scanner:2026.07-v2-control >/dev/null
      command docker image inspect arl-plus-docker-mcp-local >/dev/null
      command docker image inspect arl-plus-docker-mcp >/dev/null
      return
    fi
    shift 2
    command docker compose build --quiet "$@"
    return
  fi
  command docker "$@"
}
export -f docker

# 原回归脚本退出时会立即删除容器，导致 Actions 的失败诊断看不到现场。
# CI 副本移除 EXIT 清理 trap，并修正仅影响测试编排的问题。
python3 - .github/scripts/full-regression.sh "$runner" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding='utf-8')
source = source.replace(
    "docker exec arl-e2e-mcp-auth python - <<'PY'",
    "docker exec -i arl-e2e-mcp-auth python - <<'PY'",
    1,
)
source = source.replace(
    "docker run -d --name arl-e2e-scanner --network arl-e2e \\",
    "docker run -d --name arl-e2e-scanner --network arl-e2e --cap-drop ALL --security-opt no-new-privileges:true \\",
    1,
)
source = source.replace(
    "    -e ENABLE_NAABU=false \\",
    "    -e ENABLE_NAABU=true \\\n    -e CUSTOM_PORTS=8080 \\\n    -e NAABU_SERVICE_VERSION_OVERRIDE=false \\",
    1,
)

runtime_permissions = '''  chmod 755 "$work/results" "$work/config" "$work/templates" "$work/pocs" "$work/pocs/nuclei" "$work/pocs/afrog"
'''
runtime_permissions_fixed = runtime_permissions + '''  # 生产安装器以 root 创建这些目录；cap_drop=ALL 后容器不能绕过错误属主。
  sudo chown -R 0:0 "$work/results" "$work/config" "$work/templates"
'''
if runtime_permissions not in source:
    raise SystemExit('runtime permission block not found')
source = source.replace(runtime_permissions, runtime_permissions_fixed, 1)

compose_permissions = '''  chmod 644 "$ARL_REPORT_ROOT/index.html" "$ARL_REPORT_ROOT/xray/index.html" "$ARL_REPORT_ROOT/scanner/index.html"
'''
compose_permissions_fixed = compose_permissions + '''  # 模拟正式安装器的 root:root Scanner 写入目录。
  sudo chown 0:0 "$ARL_REPORT_ROOT/scanner"
'''
if compose_permissions not in source:
    raise SystemExit('compose permission block not found')
source = source.replace(compose_permissions, compose_permissions_fixed, 1)

old = """  docker compose exec -T web test -r /code/frontend/report/xray/index.html
  docker compose exec -T web test -r /code/frontend/report/scanner/index.html
  docker compose exec -T mcp-local python -c 'import json,urllib.request; d=json.load(urllib.request.urlopen(\"http://scanner-v2:8090/healthz\", timeout=5)); assert d[\"scanner_v2_reachable\"] is True'
  docker compose ps
"""
new = """  docker compose exec -T web test -r /code/frontend/report/xray/index.html
  docker compose exec -T web test -r /code/frontend/report/scanner/index.html
  scanner_ready=false
  for _ in $(seq 1 90); do
    if docker compose exec -T mcp-local python -c 'import json,urllib.request; d=json.load(urllib.request.urlopen(\"http://scanner-v2:8090/healthz\", timeout=5)); assert d[\"scanner_v2_reachable\"] is True' >/dev/null 2>&1; then
      scanner_ready=true
      break
    fi
    sleep 2
  done
  [[ \"$scanner_ready\" == true ]] || {
    docker compose logs --tail=200 scanner-v2 mcp-local
    die \"MCP cannot reach healthy Scanner V2\"
  }
  docker compose ps
"""
if old not in source:
    raise SystemExit('compose Scanner readiness block not found')
source = source.replace(old, new, 1)

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
