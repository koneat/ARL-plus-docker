#!/usr/bin/env bash
# ARL_PRIVATE_BOOTSTRAP_VERSION=2026.07.17-complete.2
set -Eeuo pipefail
umask 077

ENV_FILE="${ARL_ENV_FILE:-/root/arl-full.env}"
TUNNEL_ENV_FILE="${TUNNEL_ENV_FILE:-/root/tunnel-client.env}"
ARL_DIR="${ARL_DIR:-/root/ARL-plus-docker}"
REPO_URL="${REPO_URL:-https://github.com/koneat/ARL-plus-docker.git}"
RELEASE_BRANCH="${RELEASE_BRANCH:-release/2026.07.17-final}"
REVIEWED_COMMIT="${REVIEWED_COMMIT:-}"
INSTALL_TUNNEL_CLIENT="${INSTALL_TUNNEL_CLIENT:-false}"
TUNNEL_CLIENT_VERSION="${TUNNEL_CLIENT_VERSION:-v0.0.10}"
TUNNEL_PROFILE="${TUNNEL_PROFILE:-arl-mcp}"
TUNNEL_HEALTH_ADDR="${TUNNEL_HEALTH_ADDR:-127.0.0.1:8005}"
TMP_DIR=""

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

cleanup() {
  local status=$?
  [[ -z "$TMP_DIR" || ! -d "$TMP_DIR" ]] || rm -rf -- "$TMP_DIR"
  return "$status"
}
trap cleanup EXIT

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
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
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

[[ "$(id -u)" -eq 0 ]] || die '请使用 root 运行本脚本'
[[ -r /etc/os-release ]] || die '无法识别操作系统'
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || die "当前只支持 Ubuntu：${PRETTY_NAME:-unknown}"
[[ -s "$ENV_FILE" ]] || die "缺少本机私密配置：$ENV_FILE"
chmod 0600 "$ENV_FILE"

export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 -o Acquire::Retries=5 update
apt-get -o DPkg::Lock::Timeout=300 -o Acquire::Retries=5 install -y \
  ca-certificates curl git jq python3 util-linux netcat-openbsd unzip tmux wget

# 完整模式只写白名单开关；已有密钥、MongoDB URI 和情报平台 Token 保持原样。
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
set_env_value ENABLE_AFROG true
set_env_value ENABLE_FFUF true
set_env_value REPORT_ROOT /var/lib/arl-reports
set_env_value REPORT_WORLD_READABLE false
chmod 0600 "$ENV_FILE"

TMP_DIR="$(mktemp -d /tmp/arl-private-complete.XXXXXX)"
log "克隆完整发布分支：$RELEASE_BRANCH"
git -c http.version=HTTP/1.1 clone --depth 1 --single-branch \
  --branch "$RELEASE_BRANCH" "$REPO_URL" "$TMP_DIR/repo"
actual_commit="$(git -C "$TMP_DIR/repo" rev-parse HEAD)"
if [[ -n "$REVIEWED_COMMIT" && "$actual_commit" != "$REVIEWED_COMMIT" ]]; then
  die "发布分支提交不匹配：期望 $REVIEWED_COMMIT，实际 $actual_commit"
fi

grep -q '^# ARL_COMPLETE_INSTALLER_VERSION=2026.07.17-mcp-url-safe.2$' \
  "$TMP_DIR/repo/install-arl-complete.sh" || die '完整安装器版本不匹配'
bash -n "$TMP_DIR/repo/install-arl-final.sh"
bash -n "$TMP_DIR/repo/install-arl-complete.sh"

export REPO_URL RELEASE_BRANCH ARL_DIR
export REPO_BRANCH="$RELEASE_BRANCH"
export ARL_ENV_FILE="$ENV_FILE"
log '执行完整 ARL 安装器'
bash "$TMP_DIR/repo/install-arl-complete.sh"

for container in arl_worker arl_web arl_scanner_v2 arl_mcp_local arl_mcp; do
  docker inspect "$container" >/dev/null 2>&1 || die "容器不存在：$container"
done
docker exec arl_worker command -v afrog >/dev/null || die 'Worker 内没有 Afrog'
docker exec arl_worker command -v rad >/dev/null || die 'Worker 内没有 RAD'
docker exec arl_worker command -v arl-report-index >/dev/null || die 'Worker 内没有统一报告索引器'
docker exec arl_worker arl-report-index

for path in \
  /var/lib/arl-reports/index.html \
  /var/lib/arl-reports/xray/index.html \
  /var/lib/arl-reports/scanner/index.html; do
  [[ -s "$path" ]] || die "报告文件不存在：$path"
done

for url in \
  https://127.0.0.1:5003/report/ \
  https://127.0.0.1:5003/report/index.html \
  https://127.0.0.1:5003/xray/index.html \
  https://127.0.0.1:5003/report/scanner/index.html; do
  code="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 "$url")"
  [[ "$code" == 200 ]] || die "${url} HTTP 状态异常：${code}"
done

docker exec arl_mcp_local python - <<'PY' >/dev/null
import json
import urllib.request
with urllib.request.urlopen('http://scanner-v2:8090/capabilities', timeout=10) as response:
    data = json.load(response)
assert data.get('enhanced_submit_quality_upgrade') is True
assert data.get('native_restart_quality_upgrade') is False
required = {'uncover', 'subfinder', 'passive_urls', 'katana', 'tls_san', 'sourcemap', 'ffuf', 'nuclei_fail_closed', 'afrog', 'html_report'}
assert required.issubset(set(data.get('pipeline') or []))
PY

install_tunnel_client() {
  [[ "$INSTALL_TUNNEL_CLIENT" == true ]] || return 0
  [[ -s "$TUNNEL_ENV_FILE" ]] || die "启用 tunnel-client 但缺少：$TUNNEL_ENV_FILE"
  chmod 0600 "$TUNNEL_ENV_FILE"
  # shellcheck disable=SC1090
  source "$TUNNEL_ENV_FILE"
  [[ -n "${CONTROL_PLANE_API_KEY:-}" ]] || die 'CONTROL_PLANE_API_KEY 为空'
  [[ -n "${TUNNEL_ID:-}" ]] || die 'TUNNEL_ID 为空'

  archive="/root/tunnel-client.zip"
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
    bash -lc 'cd /root && rm -f "/root/.config/tunnel-client/${TUNNEL_PROFILE}.yaml" && ./tunnel-client init --profile "$TUNNEL_PROFILE" --tunnel-id "$TUNNEL_ID" --mcp-server-url http://127.0.0.1:5013/mcp && exec ./tunnel-client run --profile "$TUNNEL_PROFILE" --health.listen-addr "$TUNNEL_HEALTH_ADDR"'
  ok 'tunnel-client 已在 tmux 会话 tunnel 中启动'
}

install_tunnel_client
ok '全新机器一键安装与完整版本验收完成'
echo "固定发布分支：$RELEASE_BRANCH"
echo "实际审查提交：$actual_commit"
echo 'ARL：https://服务器IP:5003/'
echo '统一漏洞报告：https://服务器IP:5003/report/'
echo 'Xray 主入口：https://服务器IP:5003/xray/index.html'
echo 'Scanner V2 报告：https://服务器IP:5003/report/scanner/index.html'
echo '本机 MCP：http://127.0.0.1:5013/mcp（免 Token）'
echo '外部 MCP：http://服务器IP:5014/mcp（强制 Bearer Token）'
