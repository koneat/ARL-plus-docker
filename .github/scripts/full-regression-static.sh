#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

log() { printf '\n[%s] %s\n' "$(date '+%F %T')" "$*"; }

log 'Shell 语法检查'
while IFS= read -r file; do
  bash -n "$file"
done < <(find installer scripts scanner mcp enhanced-worker web-ui .github/scripts -type f -name '*.sh' | sort)
for file in enhanced-worker/arl-report-index-wrapper enhanced-worker/afrog-arl; do
  [[ -f "$file" ]] && bash -n "$file"
done
bash -n install-arl-final.sh
bash -n install-arl-complete.sh
bash -n installer/private-bootstrap.example.sh

log 'Python 语法检查'
python3 -m compileall -q scanner mcp enhanced-worker installer scripts

log 'Compose 拓扑检查'
export ARL_REPORT_ROOT="${RUNNER_TEMP:-/tmp}/arl-regression-reports"
mkdir -p "$ARL_REPORT_ROOT/scanner"
compose_rendered="${RUNNER_TEMP:-/tmp}/arl-compose-rendered.yml"
docker compose config >"$compose_rendered"
grep -q '^  scanner-v2:' "$compose_rendered"
grep -q 'target: /code/frontend/report' "$compose_rendered"
grep -q 'target: /work/results' "$compose_rendered"
! grep -q 'target: /code/frontend/report/scanner' "$compose_rendered"
! grep -Fq '/code/frontend/report/scanner:ro' docker-compose.yml
python3 - "$compose_rendered" <<'PY'
import sys
import yaml

with open(sys.argv[1], encoding='utf-8') as handle:
    services = (yaml.safe_load(handle) or {}).get('services') or {}
for name in ('mcp-local', 'mcp'):
    depends = services[name]['depends_on']
    assert depends['scanner-v2']['condition'] == 'service_healthy', (name, depends)
    assert depends['web']['condition'] == 'service_started', (name, depends)
PY

log '固定发布版本检查'
grep -Fq 'ARL_PRIVATE_BOOTSTRAP_VERSION=2026.07.17-final.1' installer/private-bootstrap.example.sh
grep -Fq 'release/2026.07.17-final' installer/private-bootstrap.example.sh
grep -Fq '7ac2c8e0aa4440672eccf163d7604c1864c2065a' installer/private-bootstrap.example.sh
grep -Fq 'ARL_COMPLETE_INSTALLER_VERSION=2026.07.17-mcp-url-safe.2' install-arl-complete.sh
grep -Fq 'https://127.0.0.1:5003/xray/index.html' installer/private-bootstrap.example.sh
grep -Fq 'arl_submit_enhanced_scan' mcp/enhanced_tools.py
grep -Fq 'legacy_native_restart' mcp/patch_server.py

log '安装器 check-only'
tmp="$(mktemp -d)"
cat >"$tmp/arl.env" <<'EOF'
ARL_MONGO_URI=''
ARL_MONGO_DB='arl'
ARL_API_KEY='ci-test-api-key-not-secret'
MCP_TOKEN='ci-test-mcp-token-0123456789abcdef0123456789abcdef'
MCP_LOCAL_BIND_IP='127.0.0.1'
MCP_LOCAL_PORT='5013'
MCP_EXTERNAL_BIND_IP='127.0.0.1'
MCP_EXTERNAL_PORT='5014'
MCP_ALLOW_LOCAL_UNAUTHENTICATED='true'
MCP_READ_ONLY='false'
DISABLE_UFW='false'
ENABLE_VLESS_PROXY='false'
ENABLE_ARL_HTTP_PROXY='false'
FORCE_ARL_PROXY='false'
ENABLE_CHAITIN_XRAY='true'
ENABLE_SMART_WILDCARD='true'
ENABLE_SCANNER_STACK='true'
BUILD_SCANNER_IMAGE='true'
ENABLE_WORKER_EXTENSIONS='true'
INSTALL_CHROMIUM='false'
REPORT_ROOT='/tmp/arl-check-reports'
REPORT_WORLD_READABLE='false'
EOF
chmod 600 "$tmp/arl.env"
bash installer/arl-full-deploy.sh --env-file "$tmp/arl.env" --check-only

log '报告权限与索引生成检查'
report_root="$tmp/reports"
sudo env REPORT_ROOT="$report_root" REPORT_WORLD_READABLE=false bash -c '
  set -Eeuo pipefail
  log(){ :; }; ok(){ :; }; warn(){ :; }; die(){ echo "$*" >&2; exit 1; }
  source installer/lib/40-reports.sh
  prepare_reports
'
test -s "$report_root/index.html"
test -s "$report_root/xray/index.html"
test "$(stat -c '%a' "$report_root")" = 755
test "$(stat -c '%a' "$report_root/xray")" = 755
test "$(stat -c '%a' "$report_root/xray/index.html")" = 644

log '敏感信息与错误挂载回归检查'
! grep -RIE --exclude-dir=.git --exclude='*.md' \
  '(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|mongodb(\+srv)?://[^[:space:]]+:[^[:space:]]+@|vless://)' .
! grep -RFn '/code/frontend/report/scanner:ro' . --exclude-dir=.git

log 'STATIC REGRESSION PASSED'
