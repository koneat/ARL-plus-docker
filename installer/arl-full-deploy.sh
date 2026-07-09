#!/usr/bin/env bash
# ARL_FULL_INSTALLER_VERSION=2026.07.09
set -Eeuo pipefail
umask 077

# 从 Git 仓库执行时，先复制部署引擎到临时目录再继续。
# 这样后续 git pull 不会在运行中替换当前脚本或已加载模块。
if [[ "${ARL_INSTALLER_REEXEC:-false}" != "true" ]]; then
  SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  CACHE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/arl-full-installer.XXXXXX")"
  cp -a "${SOURCE_DIR}/." "${CACHE_DIR}/"
  export ARL_INSTALLER_REEXEC='true'
  export ARL_INSTALLER_CACHE_DIR="$CACHE_DIR"
  exec bash "${CACHE_DIR}/arl-full-deploy.sh" "$@"
fi

INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup_installer_cache() {
  local cache="${ARL_INSTALLER_CACHE_DIR:-}"
  [[ -n "$cache" && -d "$cache" ]] || return 0
  case "$cache" in
    "${TMPDIR:-/tmp}"/arl-full-installer.*) rm -rf -- "$cache" ;;
    *) printf '[WARN] 拒绝清理异常缓存路径：%s\n' "$cache" >&2 ;;
  esac
}
trap cleanup_installer_cache EXIT

# ============================================================
# ARL Full 部署引擎
# 公开仓库只保存部署逻辑；密钥、Mongo URI、情报 API 和 VLESS 节点必须放在本机配置。
# ============================================================

ENV_FILE="${ARL_ENV_FILE:-/root/arl-full.env}"
CHECK_ONLY='false'

usage() {
  cat <<'EOF'
用法：
  bash arl-full-deploy.sh [--env-file /root/arl-full.env] [--check-only]

--env-file   加载本机敏感配置和重要参数；文件必须由可信管理员维护。
--check-only  只做语法、参数和敏感信息隔离检查，不安装、不联网、不修改系统。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      [[ $# -ge 2 ]] || { echo '[FATAL] --env-file 缺少路径' >&2; exit 2; }
      ENV_FILE="$2"
      shift 2
      ;;
    --check-only)
      CHECK_ONLY='true'
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FATAL] 未知参数：$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$ENV_FILE" ]]; then
  [[ -f "$ENV_FILE" ]] || {
    echo "[FATAL] 配置文件不存在：$ENV_FILE" >&2
    exit 1
  }
  # shellcheck disable=SC1090
  set -a
  source "$ENV_FILE"
  set +a
fi

set -a
INSTALL_ROOT="${INSTALL_ROOT:-/root}"
REPO_URL="${REPO_URL:-https://github.com/koneat/ARL-plus-docker.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
ARL_DIR="${ARL_DIR:-/root/ARL-plus-docker}"
DISABLE_UFW="${DISABLE_UFW:-false}"
CONFIG_SOURCE_URL="${CONFIG_SOURCE_URL-}"

ARL_MONGO_URI="${ARL_MONGO_URI-}"
ARL_MONGO_DB="${ARL_MONGO_DB:-arl}"
ARL_API_KEY="${ARL_API_KEY-}"
MCP_TOKEN="${MCP_TOKEN-}"

MCP_LOCAL_BIND_IP="${MCP_LOCAL_BIND_IP:-127.0.0.1}"
MCP_LOCAL_PORT="${MCP_LOCAL_PORT:-5013}"
MCP_ALLOW_LOCAL_UNAUTHENTICATED="${MCP_ALLOW_LOCAL_UNAUTHENTICATED:-true}"
MCP_EXTERNAL_BIND_IP="${MCP_EXTERNAL_BIND_IP:-127.0.0.1}"
MCP_EXTERNAL_PORT="${MCP_EXTERNAL_PORT:-5014}"
MCP_READ_ONLY="${MCP_READ_ONLY:-true}"

ARL_BIND_IP="${ARL_BIND_IP:-0.0.0.0}"
ARL_HTTPS_PORT="${ARL_HTTPS_PORT:-5003}"

FOFA_EMAIL="${FOFA_EMAIL-}"
FOFA_KEY="${FOFA_KEY-}"
HUNTER_API_KEY="${HUNTER_API_KEY-}"
QUAKE_TOKEN="${QUAKE_TOKEN-}"
ZOOMEYE_API_KEY="${ZOOMEYE_API_KEY-}"
SHODAN_API_KEY="${SHODAN_API_KEY-}"
GITHUB_TOKEN="${GITHUB_TOKEN-}"
HTTP_PROXY_URL="${HTTP_PROXY_URL-}"

ENABLE_VLESS_PROXY="${ENABLE_VLESS_PROXY:-false}"
ENABLE_ARL_HTTP_PROXY="${ENABLE_ARL_HTTP_PROXY:-false}"
FORCE_ARL_PROXY="${FORCE_ARL_PROXY:-false}"
XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-v26.3.27}"
XRAY_SOCKS_PORT="${XRAY_SOCKS_PORT:-1080}"
XRAY_PROXY_TEST_URL="${XRAY_PROXY_TEST_URL:-https://ipinfo.io/ip}"
VLESS_NODES_FILE="${VLESS_NODES_FILE:-/etc/xray-core/vless-nodes.txt}"
XRAY_CORE_CONFIG="${XRAY_CORE_CONFIG:-/etc/xray-core/config.json}"
XRAY_PROXY_HEALTHY='false'

ENABLE_CHAITIN_XRAY="${ENABLE_CHAITIN_XRAY:-false}"
CHAITIN_XRAY_VERSION="${CHAITIN_XRAY_VERSION:-1.9.11}"
CHAITIN_XRAY_PORT="${CHAITIN_XRAY_PORT:-7777}"
CHAITIN_XRAY_DIR="${CHAITIN_XRAY_DIR:-/opt/chaitin-xray}"

ENABLE_SMART_WILDCARD="${ENABLE_SMART_WILDCARD:-true}"
ENABLE_SCANNER_STACK="${ENABLE_SCANNER_STACK:-true}"
BUILD_SCANNER_IMAGE="${BUILD_SCANNER_IMAGE:-true}"
ENABLE_WORKER_EXTENSIONS="${ENABLE_WORKER_EXTENSIONS:-false}"
AFROG_VERSION="${AFROG_VERSION:-v3.5.3}"
RAD_VERSION="${RAD_VERSION:-1.0}"
REPORT_ROOT="${REPORT_ROOT:-/var/lib/arl-reports}"
REPORT_WORLD_READABLE="${REPORT_WORLD_READABLE:-false}"

AFROG_CALLBACK_DOMAIN="${AFROG_CALLBACK_DOMAIN:-callback.red}"
AFROG_CALLBACK_API_URL="${AFROG_CALLBACK_API_URL:-http://callback.red}"

API_DICT_URL="${API_DICT_URL:-https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt}"
FUZZ_DICT_URL="${FUZZ_DICT_URL:-https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt}"
DOMAIN_DICT_URL="${DOMAIN_DICT_URL:-https://raw.githubusercontent.com/TheKingOfDuck/fuzzDicts/refs/heads/master/subdomainDicts/main.txt}"
WIH_RULES_URL="${WIH_RULES_URL-}"
FILELEAK_SERVICE_URL="${FILELEAK_SERVICE_URL-}"
NUCLEI_SCAN_SERVICE_URL="${NUCLEI_SCAN_SERVICE_URL-}"
set +a

SCRIPT_NAME="$(basename "$0")"
if [[ "$CHECK_ONLY" == "true" ]]; then
  LOG_DIR="${LOG_DIR:-${TMPDIR:-/tmp}/arl-install-check}"
else
  LOG_DIR="${LOG_DIR:-/root/arl-install-logs}"
fi
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${LOG_DIR}/step1-${RUN_ID}.log"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

on_error() {
  local exit_code=$?
  local line_no="${BASH_LINENO[0]:-unknown}"
  echo "[ERROR] ${SCRIPT_NAME} 第 ${line_no} 行失败，退出码 ${exit_code}"
  echo "[ERROR] 日志：${LOG_FILE}"
  exit "$exit_code"
}
trap on_error ERR

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

for module in \
  00-core.sh \
  10-repository.sh \
  20-config-yaml.sh \
  21-secrets-env.sh \
  22-compose-file.sh \
  30-deploy.sh \
  40-reports.sh \
  50-vless-utils.sh \
  51-vless-config.sh \
  52-vless-install.sh \
  60-arl-proxy.sh \
  61-chaitin-xray.sh \
  70-afrog-rad.sh \
  71-worker-support.sh \
  80-enhancements.sh \
  90-main.sh; do
  # shellcheck disable=SC1090
  source "${INSTALLER_DIR}/lib/${module}"
done

main
