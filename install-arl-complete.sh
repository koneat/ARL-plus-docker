#!/usr/bin/env bash
# ARL_COMPLETE_INSTALLER_VERSION=2026.07.17-mcp-url-safe.1
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${ARL_FINAL_INSTALLER_CORE:-${ROOT}/install-arl-final.sh}"
[[ -r "$CORE" ]] || {
  printf '[FATAL] 完整安装核心不存在：%s\n' "$CORE" >&2
  exit 1
}

export ARL_FINAL_INSTALLER_LIBRARY_ONLY=true
# shellcheck disable=SC1090
source "$CORE"
unset ARL_FINAL_INSTALLER_LIBRARY_ONLY

host_bind_ip() {
  local container="$1"
  local host_port="$2"
  local ports_json
  ports_json="$(docker inspect -f '{{json .NetworkSettings.Ports}}' "$container")"
  python3 - "$host_port" "$ports_json" <<'PY'
import json
import sys

host_port = sys.argv[1]
container_port = f"{host_port}/tcp"
ports = json.loads(sys.argv[2])
for binding in ports.get(container_port) or []:
    if str(binding.get("HostPort")) == host_port:
        print(binding.get("HostIp") or "")
        break
PY
}

mcp_test_host() {
  local bind_ip="$1"
  python3 - "$bind_ip" <<'PY'
import ipaddress
import sys

raw = sys.argv[1].strip().strip("[]")
if not raw:
    raw = "127.0.0.1"
try:
    address = ipaddress.ip_address(raw)
except ValueError as exc:
    raise SystemExit(f"invalid MCP bind IP: {raw!r}") from exc
if address.is_unspecified:
    address = ipaddress.ip_address("::1" if address.version == 6 else "127.0.0.1")
print(f"[{address}]" if address.version == 6 else str(address))
PY
}

post_install_auth_audit() {
  local local_url external_host external_url token wrong_token
  local local_code external_code wrong_code external_auth_code
  local local_flag external_flag local_bind actual_external_bind
  local local_container_token external_container_token

  local_url='http://127.0.0.1:5013/mcp'
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
  external_host="$(mcp_test_host "$actual_external_bind")" ||
    die "认证审查失败：5014 实际绑定地址非法：${actual_external_bind@Q}"
  external_url="http://${external_host}:5014/mcp"
  [[ "$external_url" != *$'\r'* && "$external_url" != *$'\n'* && "$external_url" != *' '* ]] ||
    die "认证审查失败：外部 MCP URL 含非法字符：${external_url@Q}"

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
  echo "$local_health" | jq -e '.status == "ok" and .auth_required == false' >/dev/null ||
    die '认证审查失败：本机 healthz 内容或认证状态异常'
  echo "$external_health" | jq -e '.status == "ok" and .auth_required == true' >/dev/null ||
    die '认证审查失败：外部 healthz 内容或认证状态异常'

  ok "认证实测通过：5013 无 Token HTTP ${local_code}；5014 无 Token/错误 Token 均为 401；正确 Token HTTP ${external_auth_code}"
  ok "端口绑定通过：5013=${local_bind}；5014=${actual_external_bind}"
}

if [[ "${ARL_COMPLETE_INSTALLER_LIBRARY_ONLY:-false}" != 'true' ]]; then
  main "$@"
fi
