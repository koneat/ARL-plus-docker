#!/usr/bin/env bash
# ARL_PRIVATE_BOOTSTRAP_VERSION=2026.07.17-scanner-v2-complete.1
set -Eeuo pipefail
umask 077

# 安全模板：生产密钥、MongoDB URI、情报平台 Token、VLESS 节点和
# CONTROL_PLANE_API_KEY 必须保存在本机 0600 文件中，禁止写入本脚本或 GitHub。
ENV_FILE="${ARL_ENV_FILE:-/root/arl-full.env}"
VLESS_FILE="${VLESS_NODES_FILE:-/etc/xray-core/vless-nodes.txt}"
TUNNEL_ENV_FILE="${TUNNEL_ENV_FILE:-/root/tunnel-client.env}"
ARL_DIR="${ARL_DIR:-/root/ARL-plus-docker}"
REPO_URL="${REPO_URL:-https://github.com/koneat/ARL-plus-docker.git}"
RELEASE_BRANCH="${RELEASE_BRANCH:-release/2026.07.09-scanner-v2-control-plane}"
REVIEWED_COMMIT="${REVIEWED_COMMIT:-bc68248f782adeefa358dd23a5fde4eedd77ce73}"
FINAL_INSTALLER="${FINAL_INSTALLER:-/root/install-arl-final.sh}"
EXPECTED_INSTALLER_VERSION="2026.07.09-auth-audited.2"
INSTALL_TUNNEL_CLIENT="${INSTALL_TUNNEL_CLIENT:-false}"
TUNNEL_CLIENT_VERSION="${TUNNEL_CLIENT_VERSION:-v0.0.10}"
TUNNEL_PROFILE="${TUNNEL_PROFILE:-arl-mcp}"
TUNNEL_HEALTH_ADDR="${TUNNEL_HEALTH_ADDR:-127.0.0.1:8005}"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die '请使用 root 运行本脚本'
[[ -r /etc/os-release ]] || die '无法识别操作系统'
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "当前只支持 Ubuntu：${PRETTY_NAME:-unknown}"

apt_update_resilient() {
  local attempt max_attempts=6 delay_seconds
  for attempt in $(seq 1 "$max_attempts"); do
    if apt-get \
      -o DPkg::Lock::Timeout=300 \
      -o Binary::apt-get::DPkg::Lock::Timeout=300 \
      -o Acquire::Retries=5 \
      -o Acquire::Languages=none \
      update; then
      return 0
    fi
    if (( attempt == max_attempts )); then
      break
    fi
    delay_seconds=$((attempt * 5))
    warn "APT 索引更新失败，第 ${attempt}/${max_attempts} 次；清理损坏索引后 ${delay_seconds} 秒重试"
    rm -rf /var/lib/apt/lists/partial/*
    find /var/lib/apt/lists -maxdepth 1 -type f \
      \( -name '*Translation*' -o -name '*i18n*' \) \
      -delete 2>/dev/null || true
    apt-get clean || true
    sleep "$delay_seconds"
  done
  die "APT 索引连续 ${max_attempts} 次更新失败"
}

install_bootstrap_dependencies() {
  local missing=false command_name
  for command_name in curl git jq python3 flock nc unzip tmux wget; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing=true
      break
    fi
  done
  [[ "$missing" == false ]] && return 0

  export DEBIAN_FRONTEND=noninteractive
  apt_update_resilient
  apt-get \
    -o DPkg::Lock::Timeout=300 \
    -o Binary::apt-get::DPkg::Lock::Timeout=300 \
    -o Acquire::Retries=5 \
    -o Acquire::Languages=none \
    install -y \
    ca-certificates curl git jq python3 util-linux \
    netcat-openbsd unzip tmux wget
}

set_env_value() {
  local key="$1"
  local value="$2"
  python3 - "$ENV_FILE" "$key" "$value" <<'PY'
import os
import re
import shlex
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
    raise SystemExit("invalid env key")
lines = path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else []
pattern = re.compile(r"^[ \t]*(?:export[ \t]+)?" + re.escape(key) + r"=")
replacement = key + "=" + shlex.quote(value) + "\n"
output = []
found = False
for line in lines:
    if pattern.match(line):
        if not found:
            output.append(replacement)
            found = True
        continue
    output.append(line)
if not found:
    if output and not output[-1].endswith(("\n", "\r")):
        output[-1] += "\n"
    output.append(replacement)
path.parent.mkdir(parents=True, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.writelines(output)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

[[ -s "$ENV_FILE" ]] || die "缺少本机私密配置：$ENV_FILE"
chmod 0600 "$ENV_FILE"
if [[ -e "$VLESS_FILE" ]]; then
  chmod 0600 "$VLESS_FILE"
fi

install_bootstrap_dependencies

# 同步完整正式版本配置。敏感值保持原样，不在这里写入。
set_env_value REPO_URL "$REPO_URL"
set_env_value REPO_BRANCH "$RELEASE_BRANCH"
set_env_value ARL_DIR "$ARL_DIR"
set_env_value ENABLE_CHAITIN_XRAY true
set_env_value ENABLE_SMART_WILDCARD true
set_env_value ENABLE_SCANNER_STACK true
set_env_value BUILD_SCANNER_IMAGE true
set_env_value ENABLE_WORKER_EXTENSIONS true
set_env_value INSTALL_CHROMIUM true
set_env_value ARL_AUTO_AFROG_SCAN true
set_env_value ARL_REQUIRE_XRAY_PROXY true
set_env_value ARL_AFROG_SEVERITY 'info,low,medium,high,critical'
set_env_value ARL_AFROG_RATE_LIMIT 100
set_env_value ARL_AFROG_CONCURRENCY 20
set_env_value ARL_AFROG_TIMEOUT 20
set_env_value ARL_AFROG_MAX_TARGETS 3000
set_env_value REPORT_ROOT /var/lib/arl-reports
set_env_value REPORT_WORLD_READABLE false
set_env_value SCANNER_V2_WORKERS 1
set_env_value SCANNER_V2_MAX_QUEUE 100
set_env_value ENABLE_SUBFINDER true
set_env_value ENABLE_UNCOVER true
set_env_value ENABLE_NAABU true
set_env_value ENABLE_KATANA true
set_env_value ENABLE_SOURCEMAP true
set_env_value ENABLE_PASSIVE_URLS true
set_env_value ENABLE_TLSX true
set_env_value ENABLE_CDNCHECK true
set_env_value ENABLE_CONTENT_AUDIT true
set_env_value ENABLE_NUCLEI true
set_env_value ENABLE_NUCLEI_AUTOMATIC true
set_env_value ENABLE_NUCLEI_EXPOSURE true
set_env_value ENABLE_NUCLEI_API true
set_env_value ENABLE_NUCLEI_NETWORK true
set_env_value ENABLE_NUCLEI_DNS true
set_env_value ENABLE_AFROG true
set_env_value ENABLE_FFUF true
set_env_value NUCLEI_TEMPLATE_MIN_COUNT 50
if [[ -e "$VLESS_FILE" ]]; then
  set_env_value VLESS_NODES_FILE "$VLESS_FILE"
fi
chmod 0600 "$ENV_FILE"

TMP_DIR="$(mktemp -d /tmp/arl-private-bootstrap.XXXXXX)"
TMP_INSTALLER="$TMP_DIR/install-arl-final.sh"
trap 'rm -rf "$TMP_DIR"' EXIT

verify_final_installer() {
  local candidate="$1"
  [[ -s "$candidate" ]] || return 1
  grep -q "^# ARL_FINAL_INSTALLER_VERSION=${EXPECTED_INSTALLER_VERSION}$" "$candidate" || return 1
  bash -n "$candidate" || return 1
}

try_git_clone() {
  local clone_dir="$TMP_DIR/repo"
  rm -rf "$clone_dir"
  log "从固定发布分支克隆：$RELEASE_BRANCH"
  git -c http.version=HTTP/1.1 clone --depth 1 --single-branch \
    --branch "$RELEASE_BRANCH" "$REPO_URL" "$clone_dir" || return 1
  [[ "$(git -C "$clone_dir" rev-parse HEAD)" == "$REVIEWED_COMMIT" ]] || {
    warn '发布分支 HEAD 与固定审查提交不一致'
    return 1
  }
  verify_final_installer "$clone_dir/install-arl-final.sh" || return 1
  cp "$clone_dir/install-arl-final.sh" "$TMP_INSTALLER"
}

try_commit_download() {
  local url
  for url in \
    "https://raw.githubusercontent.com/koneat/ARL-plus-docker/${REVIEWED_COMMIT}/install-arl-final.sh" \
    "https://cdn.jsdelivr.net/gh/koneat/ARL-plus-docker@${REVIEWED_COMMIT}/install-arl-final.sh"; do
    rm -f "$TMP_INSTALLER"
    if curl --proto '=https' --tlsv1.2 -fsSL --retry 4 --retry-delay 5 \
      --connect-timeout 20 --max-time 300 \
      -A 'ARL-Private-Bootstrap/2026.07.17' "$url" -o "$TMP_INSTALLER" &&
      verify_final_installer "$TMP_INSTALLER"; then
      return 0
    fi
  done
  return 1
}

if ! try_git_clone && ! try_commit_download; then
  die '无法取得固定审查版本的最终安装器'
fi
install -m 0700 "$TMP_INSTALLER" "$FINAL_INSTALLER"

export REPO_BRANCH="$RELEASE_BRANCH"
export ARL_ENV_FILE="$ENV_FILE"
export GIT_HTTP_VERSION=HTTP/1.1
git config --global http.version HTTP/1.1 || true
bash "$FINAL_INSTALLER"

# 完整版本验收：Xray/Afrog/Scanner V2/MCP 均必须可用。
systemctl is-enabled --quiet arl-chaitin-xray.service || die '长亭 xray 未设置开机启动'
systemctl is-active --quiet arl-chaitin-xray.service || {
  systemctl --no-pager --full status arl-chaitin-xray.service || true
  journalctl -u arl-chaitin-xray.service -n 120 --no-pager || true
  die '长亭 xray 未运行'
}

docker inspect arl_worker >/dev/null 2>&1 || die 'arl_worker 不存在'
docker inspect arl_web >/dev/null 2>&1 || die 'arl_web 不存在'
docker inspect arl_scanner_v2 >/dev/null 2>&1 || die 'arl_scanner_v2 不存在'
docker inspect arl_mcp_local >/dev/null 2>&1 || die 'arl_mcp_local 不存在'
docker exec arl_worker command -v afrog >/dev/null || die 'Worker 内没有 Afrog'
docker exec arl_worker command -v arl-report-index >/dev/null || die 'Worker 内没有统一报告索引器'
docker exec arl_worker grep -q 'def afrog_scan(self):' /code/app/services/commonTask.py ||
  die 'Afrog 未挂入 ARL WebSiteFetch 任务'
docker exec arl_worker grep -q 'self.run_func("afrog_scan", self.afrog_scan)' \
  /code/app/services/commonTask.py || die 'Afrog 任务阶段未启用'

worker_env="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' arl_worker)"
grep -q '^ARL_AUTO_AFROG_SCAN=true$' <<<"$worker_env" || die 'ARL_AUTO_AFROG_SCAN 未启用'
grep -q '^ARL_REQUIRE_XRAY_PROXY=true$' <<<"$worker_env" || die 'ARL_REQUIRE_XRAY_PROXY 未启用'
XRAY_PROXY_URL="$(sed -n 's/^ARL_XRAY_PROXY_URL=//p' <<<"$worker_env" | tail -n1)"
[[ "$XRAY_PROXY_URL" == http://*:* ]] || die 'Worker 没有收到 Xray Webscan 代理地址'

docker exec arl_worker python3.6 - "$XRAY_PROXY_URL" <<'PY'
import socket
import sys
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
parsed = urlparse(sys.argv[1])
sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=5)
sock.close()
PY

docker exec arl_worker arl-report-index
test -s /var/lib/arl-reports/index.html || die '统一报告首页未生成'
test -s /var/lib/arl-reports/xray/index.html || die 'Xray 主入口未生成'
test -s /var/lib/arl-reports/scanner/index.html || die 'Scanner V2 报告首页未生成'
docker exec arl_web test -s /code/frontend/report/index.html || die 'Web 容器看不到统一报告首页'
docker exec arl_web test -s /code/frontend/report/xray/index.html || die 'Web 容器看不到 Xray 主入口'
docker exec arl_web test -s /code/frontend/report/scanner/index.html || die 'Web 容器看不到 Scanner V2 报告首页'

docker exec arl_scanner_v2 python3 - <<'PY' >/dev/null
import json
import urllib.request
with urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=8) as response:
    data = json.load(response)
assert data.get('status') == 'ok'
assert data.get('scanner_v2_reachable') is True
PY

docker exec arl_mcp_local python - <<'PY' >/dev/null
import json
import urllib.request
with urllib.request.urlopen('http://scanner-v2:8090/capabilities', timeout=10) as response:
    data = json.load(response)
assert data.get('enhanced_submit_quality_upgrade') is True
assert data.get('native_restart_quality_upgrade') is False
pipeline = set(data.get('pipeline') or [])
required = {'uncover', 'subfinder', 'passive_urls', 'katana', 'tls_san', 'sourcemap', 'ffuf', 'nuclei_fail_closed', 'afrog', 'html_report'}
assert required.issubset(pipeline)
PY

for url in \
  https://127.0.0.1:5003/report/ \
  https://127.0.0.1:5003/report/index.html \
  https://127.0.0.1:5003/xray/index.html \
  https://127.0.0.1:5003/report/scanner/index.html; do
  code="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 "$url")"
  [[ "$code" == 200 ]] || die "${url} HTTP 状态异常：${code}"
done
ok 'Afrog/Xray/Scanner V2/MCP 完整版本验收通过'

install_tunnel_client() {
  [[ "$INSTALL_TUNNEL_CLIENT" == true ]] || return 0
  [[ -s "$TUNNEL_ENV_FILE" ]] || die "启用 tunnel-client 但缺少：$TUNNEL_ENV_FILE"
  chmod 0600 "$TUNNEL_ENV_FILE"
  # shellcheck disable=SC1090
  source "$TUNNEL_ENV_FILE"
  [[ -n "${CONTROL_PLANE_API_KEY:-}" ]] || die 'CONTROL_PLANE_API_KEY 为空'
  [[ -n "${TUNNEL_ID:-}" ]] || die 'TUNNEL_ID 为空'

  local archive="/root/tunnel-client.zip"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 4 --retry-delay 5 \
    "https://github.com/openai/tunnel-client/releases/download/${TUNNEL_CLIENT_VERSION}/tunnel-client-${TUNNEL_CLIENT_VERSION}-linux-amd64.zip" \
    -o "$archive"
  unzip -oq "$archive" -d /root
  rm -f "$archive"
  chmod 0700 /root/tunnel-client

  tmux has-session -t tunnel 2>/dev/null && tmux kill-session -t tunnel
  tmux new-session -d -s tunnel env \
    CONTROL_PLANE_API_KEY="$CONTROL_PLANE_API_KEY" \
    TUNNEL_ID="$TUNNEL_ID" \
    TUNNEL_PROFILE="$TUNNEL_PROFILE" \
    TUNNEL_HEALTH_ADDR="$TUNNEL_HEALTH_ADDR" \
    bash -lc '
      set -Eeuo pipefail
      cd /root
      rm -f "/root/.config/tunnel-client/${TUNNEL_PROFILE}.yaml"
      ./tunnel-client init \
        --profile "$TUNNEL_PROFILE" \
        --tunnel-id "$TUNNEL_ID" \
        --mcp-server-url http://127.0.0.1:5013/mcp
      exec ./tunnel-client run \
        --profile "$TUNNEL_PROFILE" \
        --health.listen-addr "$TUNNEL_HEALTH_ADDR"
    '
  ok 'tunnel-client 已在 tmux 会话 tunnel 中启动'
}

install_tunnel_client

echo
ok '全新机器一键安装与完整版本验收完成'
echo "固定发布分支：$RELEASE_BRANCH"
echo "固定审查提交：$REVIEWED_COMMIT"
echo 'ARL：https://服务器IP:5003/'
echo '统一漏洞报告：https://服务器IP:5003/report/'
echo 'Xray 主入口：https://服务器IP:5003/xray/index.html'
echo 'Scanner V2 报告：https://服务器IP:5003/report/scanner/index.html'
echo '本机 MCP：http://127.0.0.1:5013/mcp（免 Token）'
echo '外部 MCP：http://服务器IP:5014/mcp（强制 Bearer Token）'
echo 'Xray 日志：journalctl -u arl-chaitin-xray.service -f'
