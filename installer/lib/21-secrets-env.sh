generate_secret() {
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(40))
PY
}

prepare_compose_env() {
  local compose_env="${ARL_DIR}/.env"

  # 重复执行时优先复用上一轮生成的 ARL API Key 和 MCP Token，
  # 避免每次重跑都改变 AI 客户端和 ARL 的认证信息。
  if [[ -f "$compose_env" ]]; then
    local saved_arl_api_key saved_mcp_token
    saved_arl_api_key="$(sed -n 's/^ARL_API_KEY=//p' "$compose_env" | head -n 1)"
    saved_mcp_token="$(sed -n 's/^MCP_TOKEN=//p' "$compose_env" | head -n 1)"

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
        lines[i] = f"  API_KEY: {json.dumps(value)}\n"
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
EOF
  chmod 600 "$compose_env"
  ok "Compose 环境文件已生成：$compose_env"
}
