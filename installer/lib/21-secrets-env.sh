generate_secret() {
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(40))
PY
}

prepare_compose_env() {
  local compose_env="${ARL_DIR}/.env"
  local env_tool="${ARL_DIR}/scripts/compose-env.py"
  local saved_arl_api_key='' saved_mcp_token=''
  local key value
  local -a persistent_keys=(ARL_WORKER_IMAGE ARL_WEB_IMAGE ARL_SCHEDULER_IMAGE)
  declare -A persistent_values=()

  [[ -f "$env_tool" ]] || die "仓库缺少 scripts/compose-env.py"

  # 重复执行时复用凭据和已经安全切换过的持久镜像选择，
  # 避免安装器覆盖 .env 后让服务退回基础镜像。
  if [[ -f "$compose_env" ]]; then
    saved_arl_api_key="$(python3 "$env_tool" "$compose_env" get ARL_API_KEY 2>/dev/null || true)"
    saved_mcp_token="$(python3 "$env_tool" "$compose_env" get MCP_TOKEN 2>/dev/null || true)"

    for key in "${persistent_keys[@]}"; do
      if python3 "$env_tool" "$compose_env" has "$key"; then
        persistent_values["$key"]="$(python3 "$env_tool" "$compose_env" get "$key")"
      fi
    done

    if [[ -z "$ARL_API_KEY" && -n "$saved_arl_api_key" ]]; then
      ARL_API_KEY="$saved_arl_api_key"
      export ARL_API_KEY
      ok "复用现有 ARL_API_KEY"
    fi

    if [[ -z "$MCP_TOKEN" && -n "$saved_mcp_token" ]]; then
      MCP_TOKEN="$saved_mcp_token"
      export MCP_TOKEN
      ok "复用现有 MCP_TOKEN"
    fi
  fi

  backup_file "$compose_env"

  if [[ -z "$ARL_API_KEY" ]]; then
    ARL_API_KEY="$(generate_secret)"
    export ARL_API_KEY
    warn "ARL_API_KEY 未填写，已自动生成"
    export TARGET_CONFIG="${ARL_DIR}/config-docker.yaml"
    python3 <<'PY'
import json
import os
import re
from pathlib import Path

path = Path(os.environ["TARGET_CONFIG"])
value = os.environ["ARL_API_KEY"]
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
in_arl = False
done = False
for i, line in enumerate(lines):
    if re.match(r"^ARL\s*:\s*$", line.rstrip()):
        in_arl = True
        continue
    if in_arl and re.match(r"^[A-Za-z0-9_]+\s*:", line) and not line.startswith(" "):
        break
    if in_arl and re.match(r"^\s{2}API_KEY\s*:", line):
        lines[i] = "  API_KEY: {}\n".format(json.dumps(value))
        done = True
        break
if not done:
    raise SystemExit("未找到 ARL.API_KEY，自动生成后无法写入")
path.write_text("".join(lines), encoding="utf-8")
PY
  fi

  if [[ -z "$MCP_TOKEN" ]]; then
    MCP_TOKEN="$(generate_secret)"
    export MCP_TOKEN
    warn "MCP_TOKEN 未填写，已自动生成"
  fi

  cat > "$compose_env" <<EOF
MCP_LOCAL_BIND_IP=${MCP_LOCAL_BIND_IP}
MCP_LOCAL_PORT=${MCP_LOCAL_PORT}
MCP_ALLOW_LOCAL_UNAUTHENTICATED=${MCP_ALLOW_LOCAL_UNAUTHENTICATED}
MCP_EXTERNAL_BIND_IP=${MCP_EXTERNAL_BIND_IP}
MCP_EXTERNAL_PORT=${MCP_EXTERNAL_PORT}
MCP_TOKEN=${MCP_TOKEN}
MCP_READ_ONLY=${MCP_READ_ONLY}
MCP_MAX_PAGE_SIZE=200
MCP_LOG_LEVEL=INFO

ARL_API_KEY=${ARL_API_KEY}
ARL_BASE_URL=https://web
ARL_VERIFY_TLS=false
ARL_TIMEOUT=30
ARL_BIND_IP=${ARL_BIND_IP}
ARL_HTTPS_PORT=${ARL_HTTPS_PORT}
ARL_REPORT_ROOT=${REPORT_ROOT}
ARL_BASE_IMAGE=${ARL_BASE_IMAGE}
ARL_ENHANCED_WORKER_IMAGE=${ARL_ENHANCED_WORKER_IMAGE}
ARL_PROXY_RUNTIME_IMAGE=${ARL_PROXY_RUNTIME_IMAGE}

AFROG_VERSION=${AFROG_VERSION}
RAD_VERSION=${RAD_VERSION}
INSTALL_CHROMIUM=${INSTALL_CHROMIUM}
AFROG_CALLBACK_DOMAIN=${AFROG_CALLBACK_DOMAIN}
AFROG_CALLBACK_API_URL=${AFROG_CALLBACK_API_URL}
REPORT_WORLD_READABLE=${REPORT_WORLD_READABLE}

ARL_NUCLEI_TAGS=${ARL_NUCLEI_TAGS}
ARL_NUCLEI_SEVERITY=${ARL_NUCLEI_SEVERITY}
ARL_NUCLEI_EXCLUDE_TAGS=${ARL_NUCLEI_EXCLUDE_TAGS}
ARL_NUCLEI_RATE_LIMIT=${ARL_NUCLEI_RATE_LIMIT}
EOF
  chmod 600 "$compose_env"

  if [[ -n "$AFROG_PROXY_URL" ]]; then
    python3 "$env_tool" "$compose_env" set AFROG_PROXY_URL "$AFROG_PROXY_URL"
  fi

  for key in "${persistent_keys[@]}"; do
    value="${persistent_values[$key]:-}"
    if [[ -n "$value" ]]; then
      python3 "$env_tool" "$compose_env" set "$key" "$value"
      ok "保留现有持久镜像选择：${key}=${value}"
    fi
  done

  ok "Compose 环境文件已生成：$compose_env"
}
