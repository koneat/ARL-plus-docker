#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-all}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

log() { printf '\n[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

cleanup_runtime() {
  docker rm -f arl-e2e-mcp-auth arl-e2e-mcp arl-e2e-scanner arl-e2e-fixture >/dev/null 2>&1 || true
  docker network rm arl-e2e >/dev/null 2>&1 || true
}
trap cleanup_runtime EXIT

static_checks() {
  log 'Shell 语法检查'
  while IFS= read -r file; do
    bash -n "$file"
  done < <(find installer scripts scanner mcp enhanced-worker web-ui .github/scripts \
    -type f -name '*.sh' -o -type f -name 'arl-report-index*' | sort)
  bash -n install-arl-final.sh
  bash -n installer/private-bootstrap.example.sh

  log 'Python 语法检查'
  python3 -m compileall -q scanner mcp enhanced-worker installer scripts

  log 'Compose 拓扑检查'
  export ARL_REPORT_ROOT="${RUNNER_TEMP:-/tmp}/arl-regression-reports"
  mkdir -p "$ARL_REPORT_ROOT/scanner"
  docker compose config >"${RUNNER_TEMP:-/tmp}/arl-compose-rendered.yml"
  grep -q '^  scanner-v2:' "${RUNNER_TEMP:-/tmp}/arl-compose-rendered.yml"
  grep -q 'target: /code/frontend/report' "${RUNNER_TEMP:-/tmp}/arl-compose-rendered.yml"
  grep -q 'target: /work/results' "${RUNNER_TEMP:-/tmp}/arl-compose-rendered.yml"
  ! grep -q 'target: /code/frontend/report/scanner' "${RUNNER_TEMP:-/tmp}/arl-compose-rendered.yml"
  ! grep -Fq '/code/frontend/report/scanner:ro' docker-compose.yml

  log '固定发布版本检查'
  grep -Fq 'ARL_PRIVATE_BOOTSTRAP_VERSION=2026.07.17-scanner-v2-complete.1' installer/private-bootstrap.example.sh
  grep -Fq 'release/2026.07.09-scanner-v2-control-plane' installer/private-bootstrap.example.sh
  grep -Fq 'bc68248f782adeefa358dd23a5fde4eedd77ce73' installer/private-bootstrap.example.sh
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
}

runtime_checks() {
  cleanup_runtime
  work="$(mktemp -d)"
  mkdir -p "$work/results" "$work/config" "$work/templates" "$work/pocs/nuclei" "$work/pocs/afrog" "$work/secrets"
  chmod 755 "$work/results" "$work/config" "$work/templates" "$work/pocs" "$work/pocs/nuclei" "$work/pocs/afrog"

  log '构建 Scanner V2 与 MCP 正式镜像'
  docker build -t arl-e2e-scanner-image ./scanner
  docker build -t arl-e2e-mcp-image ./mcp

  log '校验关键二进制'
  for tool in uncover subfinder dnsx naabu httpx urlfinder gau katana tlsx alterx cdncheck ffuf nuclei afrog nmap; do
    docker run --rm arl-e2e-scanner-image sh -lc "command -v '$tool' >/dev/null" || die "镜像缺少 $tool"
  done

  cat >"$work/fixture.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
    def send(self, code, body, content_type='text/plain'):
        raw = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        if self.path == '/':
            self.send(200, '<html><body><a href="/health">health</a><script src="/static/app.js"></script><a href="/swagger.json">api</a></body></html>', 'text/html')
        elif self.path == '/health':
            self.send(200, 'fixture-ok')
        elif self.path == '/static/app.js':
            self.send(200, 'fetch("/api/users?id=1");\n//# sourceMappingURL=app.js.map', 'application/javascript')
        elif self.path == '/static/app.js.map':
            self.send(200, json.dumps({'version': 3, 'sources': ['src/app.ts'], 'mappings': ''}), 'application/json')
        elif self.path == '/swagger.json':
            self.send(200, json.dumps({'openapi':'3.0.0','info':{'title':'fixture','version':'1'},'paths':{'/api/users':{'get':{'responses':{'200':{'description':'ok'}}}}}}), 'application/json')
        elif self.path.startswith('/api/users'):
            self.send(200, json.dumps({'id': 1, 'name': 'fixture'}), 'application/json')
        elif self.path == '/robots.txt':
            self.send(200, 'Disallow: /admin')
        elif self.path == '/admin':
            self.send(403, 'forbidden')
        else:
            self.send(404, 'not-found')

ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
PY

  cat >"$work/templates/local-fixture.yaml" <<'YAML'
id: arl-local-fixture
info:
  name: ARL local fixture
  author: regression
  severity: high
http:
  - method: GET
    path:
      - '{{BaseURL}}/health'
    matchers:
      - type: word
        words:
          - fixture-ok
YAML
  cp "$work/templates/local-fixture.yaml" "$work/pocs/nuclei/local-fixture.yaml"

  docker network create arl-e2e >/dev/null
  docker run -d --name arl-e2e-fixture --network arl-e2e --network-alias fixture.test \
    -v "$work/fixture.py:/fixture.py:ro" python:3.12-alpine python /fixture.py >/dev/null

  log '启动 Scanner V2 内部 API'
  docker run -d --name arl-e2e-scanner --network arl-e2e \
    -e SCANNER_V2_HOST=0.0.0.0 \
    -e SCANNER_V2_PORT=8090 \
    -e SCANNER_V2_WORKERS=1 \
    -e SCANNER_V2_MAX_QUEUE=10 \
    -e SCAN_MODE=fast \
    -e UPDATE_TEMPLATES=false \
    -e ENABLE_SUBFINDER=false \
    -e ENABLE_UNCOVER=false \
    -e ENABLE_NAABU=false \
    -e ENABLE_KATANA=true \
    -e ENABLE_SOURCEMAP=true \
    -e ENABLE_PASSIVE_URLS=false \
    -e ENABLE_TLSX=false \
    -e ENABLE_CDNCHECK=false \
    -e ENABLE_ALTERX=false \
    -e ENABLE_SECONDARY_CRAWL=false \
    -e ENABLE_SOURCEMAP_V2=true \
    -e ENABLE_FFUF_V2=true \
    -e ENABLE_CONTENT_AUDIT=true \
    -e ENABLE_NUCLEI=true \
    -e NUCLEI_POLICY=safe \
    -e NUCLEI_TEMPLATE_DIR=/root/nuclei-templates \
    -e NUCLEI_TEMPLATE_MIN_COUNT=1 \
    -e ENABLE_NUCLEI_AUTOMATIC=false \
    -e ENABLE_NUCLEI_EXPOSURE=false \
    -e ENABLE_NUCLEI_API=false \
    -e ENABLE_NUCLEI_NETWORK=false \
    -e ENABLE_NUCLEI_DNS=false \
    -e ENABLE_AFROG=false \
    -e ENABLE_FFUF=true \
    -v "$work/results:/work/results" \
    -v "$work/config:/root/.config" \
    -v "$work/templates:/root/nuclei-templates:ro" \
    -v "$work/pocs/nuclei:/opt/pocs/nuclei:ro" \
    -v "$work/pocs/afrog:/opt/pocs/afrog:ro" \
    -v "$work/secrets:/run/secrets:ro" \
    arl-e2e-scanner-image python3 /opt/scanner/scanner_api.py >/dev/null

  for _ in $(seq 1 120); do
    docker exec arl-e2e-scanner python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8090/healthz", timeout=3)' >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec arl-e2e-scanner python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8090/healthz", timeout=3)' >/dev/null

  log '通过 Scanner API 提交真实本地增强扫描'
  scan_id="$(docker exec -i arl-e2e-scanner python3 - <<'PY'
import json, time, urllib.request
payload = json.dumps({'name':'full-regression','targets':'http://fixture.test:8080','mode':'fast'}).encode()
req = urllib.request.Request('http://127.0.0.1:8090/scans', data=payload, headers={'Content-Type':'application/json'}, method='POST')
with urllib.request.urlopen(req, timeout=10) as response:
    data = json.load(response)
scan_id = data['scan_id']
for _ in range(600):
    with urllib.request.urlopen('http://127.0.0.1:8090/scans/' + scan_id, timeout=10) as response:
        state = json.load(response)
    if state.get('status') in {'completed','failed','interrupted'}:
        if state.get('status') != 'completed':
            raise SystemExit(json.dumps(state, ensure_ascii=False))
        print(scan_id)
        break
    time.sleep(1)
else:
    raise SystemExit('scan timeout')
PY
)"
  test -n "$scan_id"
  test -s "$work/results/$scan_id/report.html"
  test -s "$work/results/$scan_id/summary.json"
  test -s "$work/results/$scan_id/quality-status.json"
  test -s "$work/results/$scan_id/nuclei-status.json"
  jq -e '.scanner_v2 == true and .quality_upgrade == true' "$work/results/$scan_id/quality-status.json"
  jq -e '.status == "completed_findings" and .findings_count >= 1' "$work/results/$scan_id/nuclei-status.json"
  grep -Fq 'fixture.test' "$work/results/$scan_id/report.html"
  grep -Fq "$scan_id/report.html" "$work/results/index.html"

  log '验证 Scanner 状态重启持久化'
  docker restart arl-e2e-scanner >/dev/null
  for _ in $(seq 1 60); do
    docker exec arl-e2e-scanner python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8090/healthz", timeout=3)' >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec arl-e2e-scanner python3 -c "import json,urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8090/scans/$scan_id')); assert data['status']=='completed'"

  log '启动 MCP 并通过正式 MCP 客户端调用四个增强工具'
  docker run -d --name arl-e2e-mcp --network arl-e2e \
    -e MCP_HOST=0.0.0.0 -e MCP_PORT=5013 \
    -e MCP_READ_ONLY=false -e MCP_ALLOW_UNAUTHENTICATED=true \
    -e SCANNER_V2_BASE_URL=http://arl-e2e-scanner:8090 \
    -e ARL_BASE_URL=https://127.0.0.1:9 \
    arl-e2e-mcp-image >/dev/null
  for _ in $(seq 1 60); do
    docker exec arl-e2e-mcp python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:5013/healthz", timeout=3)' >/dev/null 2>&1 && break
    sleep 1
  done

  docker exec -i arl-e2e-mcp python - <<'PY'
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def main():
    async with streamablehttp_client('http://127.0.0.1:5013/mcp') as streams:
        read_stream, write_stream = streams[0], streams[1]
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = {item.name for item in listed.tools}
            required = {
                'arl_scan_capabilities',
                'arl_submit_enhanced_scan',
                'arl_get_enhanced_scan',
                'arl_get_enhanced_scan_summary',
            }
            assert required.issubset(names), sorted(required - names)
            result = await session.call_tool('arl_scan_capabilities', {})
            assert not result.isError, result
            text = ''.join(getattr(item, 'text', '') for item in result.content)
            assert 'enhanced_submit_quality_upgrade' in text
            assert 'legacy_native_restart' in text

asyncio.run(main())
PY

  log '验证 MCP 外部入口强制 Bearer Token'
  docker run -d --name arl-e2e-mcp-auth --network arl-e2e \
    -e MCP_HOST=0.0.0.0 -e MCP_PORT=5013 \
    -e MCP_TOKEN='regression-token-0123456789abcdef0123456789abcdef' \
    -e MCP_READ_ONLY=false -e MCP_ALLOW_UNAUTHENTICATED=false \
    -e SCANNER_V2_BASE_URL=http://arl-e2e-scanner:8090 \
    -e ARL_BASE_URL=https://127.0.0.1:9 \
    arl-e2e-mcp-image >/dev/null
  for _ in $(seq 1 60); do
    docker exec arl-e2e-mcp-auth python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:5013/healthz", timeout=3)' >/dev/null 2>&1 && break
    sleep 1
  done
  code="$(docker exec arl-e2e-mcp-auth python - <<'PY'
import urllib.error, urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:5013/mcp', timeout=5)
except urllib.error.HTTPError as exc:
    print(exc.code)
PY
)"
  test "$code" = 401

  docker exec -i arl-e2e-mcp-auth python - <<'PY'
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def main():
    headers = {'Authorization': 'Bearer regression-token-0123456789abcdef0123456789abcdef'}
    async with streamablehttp_client('http://127.0.0.1:5013/mcp', headers=headers) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert any(item.name == 'arl_scan_capabilities' for item in tools.tools)

asyncio.run(main())
PY

  log '日志错误检查'
  for container in arl-e2e-scanner arl-e2e-mcp arl-e2e-mcp-auth; do
    docker logs "$container" 2>&1 | tee "$work/$container.log"
    ! grep -Eiq 'Traceback|Unhandled exception|segmentation fault|panic:' "$work/$container.log"
  done
}

compose_runtime_checks() {
  log '真实 Compose Web/Scanner/MCP 挂载与 HTTP 入口检查'
  work="$(mktemp -d)"
  export ARL_REPORT_ROOT="$work/reports"
  mkdir -p "$ARL_REPORT_ROOT/xray" "$ARL_REPORT_ROOT/scanner" "$ARL_REPORT_ROOT/afrog"
  printf '<html>report-ok</html>\n' >"$ARL_REPORT_ROOT/index.html"
  cp "$ARL_REPORT_ROOT/index.html" "$ARL_REPORT_ROOT/xray/index.html"
  printf '<html>scanner-ok</html>\n' >"$ARL_REPORT_ROOT/scanner/index.html"
  chmod 755 "$ARL_REPORT_ROOT" "$ARL_REPORT_ROOT/xray" "$ARL_REPORT_ROOT/scanner" "$ARL_REPORT_ROOT/afrog"
  chmod 644 "$ARL_REPORT_ROOT/index.html" "$ARL_REPORT_ROOT/xray/index.html" "$ARL_REPORT_ROOT/scanner/index.html"

  touch arl_web.log
  docker volume create arl_db >/dev/null
  docker compose build scanner-v2 mcp-local mcp
  docker compose up -d mongodb rabbitmq web scanner-v2 mcp-local
  trap 'docker compose down -v --remove-orphans >/dev/null 2>&1 || true; docker volume rm arl_db >/dev/null 2>&1 || true; cleanup_runtime' EXIT

  for _ in $(seq 1 120); do
    curl -kfsS https://127.0.0.1:5003/report/index.html >/dev/null 2>&1 && break
    sleep 2
  done
  for path in /report/ /report/index.html /xray/index.html /report/scanner/index.html; do
    code="$(curl -k -sS -o /tmp/arl-regression-body -w '%{http_code}' --connect-timeout 5 --max-time 15 "https://127.0.0.1:5003$path")"
    test "$code" = 200 || { docker compose logs --tail=200 web scanner-v2; die "$path returned $code"; }
  done
  docker compose exec -T web test -r /code/frontend/report/xray/index.html
  docker compose exec -T web test -r /code/frontend/report/scanner/index.html
  docker compose exec -T mcp-local python -c 'import json,urllib.request; d=json.load(urllib.request.urlopen("http://scanner-v2:8090/healthz", timeout=5)); assert d["scanner_v2_reachable"] is True'
  docker compose ps
  docker compose down -v --remove-orphans
  docker volume rm arl_db >/dev/null 2>&1 || true
}

case "$MODE" in
  static) static_checks ;;
  runtime) runtime_checks ;;
  compose) compose_runtime_checks ;;
  all) static_checks; runtime_checks; compose_runtime_checks ;;
  *) die "unknown mode: $MODE" ;;
esac

log "FULL REGRESSION PASSED: $MODE"
