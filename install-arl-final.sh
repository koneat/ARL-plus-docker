#!/usr/bin/env bash
# ARL_FINAL_INSTALLER_VERSION=2026.07.09-auth-audited.2
set -Eeuo pipefail
umask 077

REPO_URL="${REPO_URL:-https://github.com/koneat/ARL-plus-docker.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
ARL_DIR="${ARL_DIR:-/root/ARL-plus-docker}"
ENV_FILE="${ARL_ENV_FILE:-/root/arl-full.env}"
LOCK_FILE="${ARL_INSTALL_LOCK_FILE:-/var/lock/arl-full-install.lock}"
BOOTSTRAP_LOG_DIR="${ARL_BOOTSTRAP_LOG_DIR:-/root/arl-install-logs}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
BOOTSTRAP_LOG="${BOOTSTRAP_LOG_DIR}/bootstrap-${RUN_ID}.log"
TMP_REPO=""

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

cleanup() {
  local status=$?
  if [[ -n "$TMP_REPO" && -d "$TMP_REPO" ]]; then
    rm -rf -- "$TMP_REPO"
  fi
  return "$status"
}
trap cleanup EXIT

on_error() {
  local status=$?
  local line="${BASH_LINENO[0]:-unknown}"
  printf '[ERROR] 最终安装脚本第 %s 行失败，退出码 %s\n' "$line" "$status" >&2
  printf '[ERROR] 启动日志：%s\n' "$BOOTSTRAP_LOG" >&2
  exit "$status"
}
trap on_error ERR

require_root_and_ubuntu() {
  [[ "$(id -u)" -eq 0 ]] || die '请使用 root 运行本脚本'
  [[ -r /etc/os-release ]] || die '无法识别操作系统'
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == 'ubuntu' ]] || die "当前只支持 Ubuntu，检测到：${PRETTY_NAME:-unknown}"
}

apt_install_bootstrap_tools() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get \
    -o DPkg::Lock::Timeout=300 \
    -o Binary::apt-get::DPkg::Lock::Timeout=300 \
    -o Acquire::Retries=5 \
    update
  apt-get \
    -o DPkg::Lock::Timeout=300 \
    -o Binary::apt-get::DPkg::Lock::Timeout=300 \
    -o Acquire::Retries=5 \
    install -y ca-certificates curl git python3 util-linux jq
}

read_env_value() {
  local file="$1"
  local key="$2"
  [[ -f "$file" ]] || return 1
  python3 - "$file" "$key" <<'PY'
from __future__ import annotations
import re
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
pattern = re.compile(rf"^[ \t]*(?:export[ \t]+)?{re.escape(key)}=(.*)$")
value = None
for raw in path.read_text(encoding="utf-8").splitlines():
    match = pattern.match(raw)
    if not match:
        continue
    text = match.group(1).strip()
    try:
        parsed = shlex.split(text, posix=True)
    except ValueError:
        raise SystemExit(2)
    value = parsed[0] if parsed else ""
if value is None:
    raise SystemExit(1)
print(value)
PY
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  python3 - "$file" "$key" "$value" <<'PY'
from __future__ import annotations
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
    raise SystemExit(f"invalid key: {key!r}")
lines = path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else []
pattern = re.compile(rf"^[ \t]*(?:export[ \t]+)?{re.escape(key)}=")
replacement = f"{key}={shlex.quote(value)}\n"
found = False
output = []
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
mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.writelines(output)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
}

prepare_private_env() {
  local backup=''
  mkdir -p "$(dirname "$ENV_FILE")"

  if [[ -f "$ENV_FILE" ]]; then
    backup="${ENV_FILE}.bak.${RUN_ID}"
    cp -a "$ENV_FILE" "$backup"
    chmod 600 "$backup"
    ok "已备份现有私密配置：$backup"
  else
    install -m 600 /dev/null "$ENV_FILE"
    cat >"$ENV_FILE" <<'EOF'
# ARL 私密生产配置。权限必须保持 600，不要提交到 GitHub。
# ARL_MONGO_URI 留空时使用本地 MongoDB 容器。
ARL_MONGO_URI=''
ARL_MONGO_DB='arl'
ARL_API_KEY=''
MCP_TOKEN=''

FOFA_EMAIL=''
FOFA_KEY=''
HUNTER_API_KEY=''
QUAKE_TOKEN=''
ZOOMEYE_API_KEY=''
SHODAN_API_KEY=''
GITHUB_TOKEN=''

ENABLE_VLESS_PROXY='false'
ENABLE_ARL_HTTP_PROXY='false'
FORCE_ARL_PROXY='false'
XRAY_CORE_VERSION='v26.3.27'
XRAY_SOCKS_PORT='1080'
VLESS_NODES_FILE='/etc/xray-core/vless-nodes.txt'

ENABLE_CHAITIN_XRAY='false'
CHAITIN_XRAY_VERSION='1.9.11'
CHAITIN_XRAY_PORT='7777'
EOF
    ok "已创建私密配置模板：$ENV_FILE"
  fi

  chmod 600 "$ENV_FILE"

  set_env_value "$ENV_FILE" REPO_URL "$REPO_URL"
  set_env_value "$ENV_FILE" REPO_BRANCH "$REPO_BRANCH"
  set_env_value "$ENV_FILE" ARL_DIR "$ARL_DIR"

  # 5013 只能绑定回环地址，免认证不会暴露到外网。
  set_env_value "$ENV_FILE" MCP_LOCAL_BIND_IP '127.0.0.1'
  set_env_value "$ENV_FILE" MCP_LOCAL_PORT '5013'
  set_env_value "$ENV_FILE" MCP_ALLOW_LOCAL_UNAUTHENTICATED 'true'

  # 5014 使用独立 MCP 容器，Compose 中无条件写死强制 Token。
  local external_bind
  external_bind="$(read_env_value "$ENV_FILE" MCP_EXTERNAL_BIND_IP 2>/dev/null || true)"
  case "$external_bind" in
    '') external_bind='127.0.0.1' ;;
    '127.0.0.1'|'::1'|'0.0.0.0'|'::') ;;
    *) die "MCP_EXTERNAL_BIND_IP 非法：${external_bind}" ;;
  esac
  set_env_value "$ENV_FILE" MCP_EXTERNAL_BIND_IP "$external_bind"
  set_env_value "$ENV_FILE" MCP_EXTERNAL_PORT '5014'

  # 允许 MCP 提交、停止和重启 ARL 任务；认证边界不受此项影响。
  set_env_value "$ENV_FILE" MCP_READ_ONLY 'false'

  local disable_ufw
  disable_ufw="$(read_env_value "$ENV_FILE" DISABLE_UFW 2>/dev/null || true)"
  set_env_value "$ENV_FILE" DISABLE_UFW "${disable_ufw:-false}"

  set_env_value "$ENV_FILE" ARL_BIND_IP '0.0.0.0'
  set_env_value "$ENV_FILE" ARL_HTTPS_PORT '5003'
  set_env_value "$ENV_FILE" ARL_BASE_IMAGE 'ki9mu/arl-ki9mu:v3.0.1'
  set_env_value "$ENV_FILE" ARL_ENHANCED_WORKER_IMAGE 'arl-enhanced-worker:v3.0.1-2026.07'
  set_env_value "$ENV_FILE" ARL_PROXY_RUNTIME_IMAGE 'arl-proxy-runtime:v3.0.1-2026.07'

  set_env_value "$ENV_FILE" ENABLE_SMART_WILDCARD 'true'
  set_env_value "$ENV_FILE" ENABLE_SCANNER_STACK 'true'
  set_env_value "$ENV_FILE" BUILD_SCANNER_IMAGE 'true'
  set_env_value "$ENV_FILE" ENABLE_WORKER_EXTENSIONS 'true'
  set_env_value "$ENV_FILE" INSTALL_CHROMIUM 'true'
  set_env_value "$ENV_FILE" AFROG_VERSION 'v3.5.3'
  set_env_value "$ENV_FILE" RAD_VERSION '1.0'
  set_env_value "$ENV_FILE" REPORT_ROOT '/var/lib/arl-reports'
  set_env_value "$ENV_FILE" REPORT_WORLD_READABLE 'false'
  set_env_value "$ENV_FILE" AFROG_CALLBACK_DOMAIN 'callback.red'
  set_env_value "$ENV_FILE" AFROG_CALLBACK_API_URL 'http://callback.red'

  set_env_value "$ENV_FILE" ARL_NUCLEI_TAGS 'cve,exposure,config,files,backup,token,logs,debug,misconfig,api,swagger,openapi,graphql,webhook'
  set_env_value "$ENV_FILE" ARL_NUCLEI_SEVERITY 'info,low,medium,high,critical'
  set_env_value "$ENV_FILE" ARL_NUCLEI_EXCLUDE_TAGS 'dos,fuzz,intrusive,bruteforce'
  set_env_value "$ENV_FILE" ARL_NUCLEI_RATE_LIMIT '120'

  local configured_token
  configured_token="$(read_env_value "$ENV_FILE" MCP_TOKEN 2>/dev/null || true)"
  if [[ -n "$configured_token" && ${#configured_token} -lt 32 ]]; then
    die '现有 MCP_TOKEN 少于 32 个字符。为避免破坏已有客户端，脚本不会自动轮换；请清空它让安装器生成强 Token，或手工换成至少 32 字符的随机值。'
  fi

  if [[ "$external_bind" == '0.0.0.0' || "$external_bind" == '::' ]]; then
    warn "外部 MCP 将直接监听所有网卡 ${external_bind}:5014；Token 仍强制，但更推荐 127.0.0.1 配合反向代理。"
  else
    ok "认证拓扑已固定：127.0.0.1:5013 本机免 Token；${external_bind}:5014 强制 Token"
  fi
}

clone_clean_installer() {
  TMP_REPO="$(mktemp -d "${TMPDIR:-/tmp}/arl-final-installer.XXXXXX")"
  git clone --depth 1 --branch "$REPO_BRANCH" --single-branch "$REPO_URL" "$TMP_REPO/repo"
  [[ -f "$TMP_REPO/repo/installer/arl-full-deploy.sh" ]] || die '仓库缺少完整部署引擎'
  [[ -f "$TMP_REPO/repo/mcp/server.py" ]] || die '仓库缺少 MCP 服务代码'
}

audit_repository_auth_design() {
  local compose="$TMP_REPO/repo/docker-compose.yml"
  local server="$TMP_REPO/repo/mcp/server.py"

  grep -q 'MCP_ALLOW_UNAUTHENTICATED=${MCP_ALLOW_LOCAL_UNAUTHENTICATED:-true}' "$compose" ||
    die '认证审查失败：本机 MCP 入口配置不符合预期'
  grep -q 'MCP_ALLOW_UNAUTHENTICATED=false' "$compose" ||
    die '认证审查失败：外部 MCP 入口没有强制关闭免认证'
  grep -q 'MCP_LOCAL_BIND_IP:-127.0.0.1' "$compose" ||
    die '认证审查失败：本机 MCP 默认未绑定 127.0.0.1'
  grep -q 'MCP_EXTERNAL_PORT:-5014' "$compose" ||
    die '认证审查失败：外部 MCP 端口不是 5014'
  grep -q 'secrets.compare_digest' "$server" ||
    die '认证审查失败：MCP Token 未使用常量时间比较'
  grep -q 'WWW-Authenticate.*Bearer' "$server" ||
    die '认证审查失败：MCP 未返回 Bearer 认证挑战'
  grep -q 'authorization.lower().startswith("bearer ")' "$server" ||
    die '认证审查失败：MCP 未解析 Authorization Bearer'
  grep -q 'headers.get("x-mcp-token"' "$server" ||
    die '认证审查失败：MCP 兼容 Token 请求头逻辑缺失'
  ok '仓库认证设计静态审查通过'
}

run_deployment() {
  log '先执行完整安装器静态检查'
  bash "$TMP_REPO/repo/installer/arl-full-deploy.sh" \
    --env-file "$ENV_FILE" \
    --check-only

  log '静态检查通过，开始正式部署'
  bash "$TMP_REPO/repo/installer/arl-full-deploy.sh" --env-file "$ENV_FILE"
}

credential_value() {
  local key="$1"
  local credentials='/root/arl-deploy-credentials.txt'
  [[ -f "$credentials" ]] || return 1
  sed -n "s/^${key}=//p" "$credentials" | tail -n 1
}

http_code() {
  curl -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 10 "$@"
}

container_env_value() {
  local container="$1"
  local key="$2"
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container" |
    sed -n "s/^${key}=//p" | tail -n 1
}

host_bind_ip() {
  local container="$1"
  local host_port="$2"
  local ports_json
  ports_json="$(docker inspect -f '{{json .NetworkSettings.Ports}}' "$container")"
  python3 - "$host_port" "$ports_json" <<'PY'
import json
import sys

host_port = sys.argv[1]
ports = json.loads(sys.argv[2])
for binding in ports.get("5013/tcp") or []:
    if str(binding.get("HostPort")) == host_port:
        print(binding.get("HostIp") or "")
        break
PY
}

mcp_test_host() {
  local bind_ip="$1"
  case "$bind_ip" in
    '::'|'::1') printf '[::1]' ;;
    '0.0.0.0') printf '127.0.0.1' ;;
    *) printf '%s' "${bind_ip:-127.0.0.1}" ;;
  esac
}

post_install_auth_audit() {
  local local_url external_bind external_host external_url token wrong_token
  local local_code external_code wrong_code external_auth_code
  local local_flag external_flag local_bind actual_external_bind
  local local_container_token external_container_token

  local_url='http://127.0.0.1:5013/mcp'
  external_bind="$(read_env_value "$ENV_FILE" MCP_EXTERNAL_BIND_IP 2>/dev/null || true)"
  external_host="$(mcp_test_host "$external_bind")"
  external_url="http://${external_host}:5014/mcp"
  token="$(credential_value MCP_TOKEN || true)"
  wrong_token='definitely-wrong-mcp-token-for-auth-audit'

  [[ ${#token} -ge 32 ]] || die '认证审查失败：部署后的 MCP_TOKEN 不存在或少于 32 字符'

  local_flag="$(container_env_value arl_mcp_local MCP_ALLOW_UNAUTHENTICATED)"
  external_flag="$(container_env_value arl_mcp MCP_ALLOW_UNAUTHENTICATED)"
  [[ "$local_flag" == 'true' ]] || die "认证审查失败：arl_mcp_local 免认证标志为 ${local_flag:-empty}"
  [[ "$external_flag" == 'false' ]] || die "认证审查失败：arl_mcp 外部入口免认证标志为 ${external_flag:-empty}"

  local_container_token="$(container_env_value arl_mcp_local MCP_TOKEN)"
  external_container_token="$(container_env_value arl_mcp MCP_TOKEN)"
  [[ "$local_container_token" == "$token" ]] || die '认证审查失败：本机 MCP 容器 Token 与凭据文件不一致'
  [[ "$external_container_token" == "$token" ]] || die '认证审查失败：外部 MCP 容器 Token 与凭据文件不一致'

  local_bind="$(host_bind_ip arl_mcp_local 5013)"
  [[ "$local_bind" == '127.0.0.1' || "$local_bind" == '::1' ]] ||
    die "认证审查失败：5013 绑定到 ${local_bind:-unknown}，必须只绑定回环地址"

  actual_external_bind="$(host_bind_ip arl_mcp 5014)"
  [[ -n "$actual_external_bind" ]] || die '认证审查失败：没有找到外部 MCP 5014 端口映射'

  local_code="$(http_code "$local_url")"
  [[ "$local_code" != '401' && "$local_code" != '403' ]] ||
    die "认证审查失败：本机 5013 无 Token 被拒绝，HTTP ${local_code}"

  external_code="$(http_code "$external_url")"
  [[ "$external_code" == '401' ]] ||
    die "认证审查失败：外部 5014 无 Token 应返回 401，实际 HTTP ${external_code}"

  wrong_code="$(http_code -H "Authorization: Bearer ${wrong_token}" "$external_url")"
  [[ "$wrong_code" == '401' ]] ||
    die "认证审查失败：外部 5014 错误 Token 应返回 401，实际 HTTP ${wrong_code}"

  external_auth_code="$(http_code -H "Authorization: Bearer ${token}" "$external_url")"
  [[ "$external_auth_code" != '401' && "$external_auth_code" != '403' ]] ||
    die "认证审查失败：外部 5014 使用正确 Token 仍被拒绝，HTTP ${external_auth_code}"

  local local_health external_health
  local_health="$(curl -fsS --connect-timeout 3 --max-time 10 http://127.0.0.1:5013/healthz)"
  external_health="$(curl -fsS --connect-timeout 3 --max-time 10 "http://${external_host}:5014/healthz")"
  echo "$local_health" | jq -e '
    .status == "ok" and
    .auth_required == false and
    ((keys - ["auth_required", "read_only", "service", "status"]) | length == 0)
  ' >/dev/null || die '认证审查失败：本机 healthz 内容或认证状态异常'
  echo "$external_health" | jq -e '
    .status == "ok" and
    .auth_required == true and
    ((keys - ["auth_required", "read_only", "service", "status"]) | length == 0)
  ' >/dev/null || die '认证审查失败：外部 healthz 内容或认证状态异常'

  ok "认证实测通过：5013 无 Token HTTP ${local_code}；5014 无 Token/错误 Token 均为 401；正确 Token HTTP ${external_auth_code}"
  ok "端口绑定通过：5013=${local_bind}；5014=${actual_external_bind}"
}

print_result() {
  local credentials='/root/arl-deploy-credentials.txt'
  local external_bind external_display
  external_bind="$(read_env_value "$ENV_FILE" MCP_EXTERNAL_BIND_IP 2>/dev/null || true)"
  external_display="$(mcp_test_host "$external_bind")"

  echo
  echo '================ ARL 最终安装完成 ================'
  echo "仓库：${ARL_DIR}"
  echo "私密配置：${ENV_FILE}"
  echo "凭据文件：${credentials}"
  echo 'MCP 本机：http://127.0.0.1:5013/mcp（免 Token，仅本机）'
  echo "MCP 外部：http://${external_display}:5014/mcp（强制 Bearer Token）"
  echo '查看 Token：grep ^MCP_TOKEN= /root/arl-deploy-credentials.txt'
  echo "启动日志：${BOOTSTRAP_LOG}"
  echo '回滚 Worker：bash /root/ARL-plus-docker/scripts/rollback-enhanced-worker.sh'
  echo '===================================================='
}

main() {
  require_root_and_ubuntu
  mkdir -p "$BOOTSTRAP_LOG_DIR" "$(dirname "$LOCK_FILE")"
  touch "$BOOTSTRAP_LOG"
  chmod 600 "$BOOTSTRAP_LOG"
  exec > >(tee -a "$BOOTSTRAP_LOG") 2>&1

  command -v flock >/dev/null 2>&1 || apt_install_bootstrap_tools
  exec 9>"$LOCK_FILE"
  flock -n 9 || die '已有另一个 ARL 安装/更新进程正在运行'

  for command in git curl python3 jq; do
    command -v "$command" >/dev/null 2>&1 || {
      apt_install_bootstrap_tools
      break
    }
  done

  prepare_private_env
  clone_clean_installer
  audit_repository_auth_design
  run_deployment
  post_install_auth_audit
  print_result
}

if [[ "${ARL_FINAL_INSTALLER_LIBRARY_ONLY:-false}" != 'true' ]]; then
  main "$@"
fi
