# shellcheck shell=bash

set_arl_http_proxy() {
  [[ "$ENABLE_ARL_HTTP_PROXY" == "true" ]] || {
    ok "未把 ARL HTTP 流量接入 VLESS 代理"
    return 0
  }
  [[ "$ENABLE_VLESS_PROXY" == "true" ]] ||
    die "ENABLE_ARL_HTTP_PROXY=true 时必须启用 ENABLE_VLESS_PROXY"

  if [[ "${XRAY_PROXY_HEALTHY:-false}" != "true" && "$FORCE_ARL_PROXY" != "true" ]]; then
    warn "VLESS 出口验证未通过，为避免 ARL 断网，本次不写入 ARL HTTP 代理"
    warn "确认节点可用后重新运行，或把 FORCE_ARL_PROXY 改为 true"
    return 0
  fi

  HTTP_PROXY_URL="socks5://${DOCKER_GATEWAY}:${XRAY_SOCKS_PORT}"
  export HTTP_PROXY_URL

  python3 - "${ARL_DIR}/config-docker.yaml" "$HTTP_PROXY_URL" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

section = None
section_end = len(lines)
for i, line in enumerate(lines):
    if re.match(r"^PROXY\s*:\s*$", line.rstrip()):
        section = i
        continue
    if section is not None and i > section and line.strip() and not line.startswith((" ", "\t", "#")):
        section_end = i
        break

if section is None:
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines += ["\nPROXY:\n", "  HTTP_URL: {}\n".format(json.dumps(value))]
else:
    replaced = False
    for i in range(section + 1, section_end):
        if re.match(r"^\s{2}HTTP_URL\s*:", lines[i]):
            lines[i] = "  HTTP_URL: {}\n".format(json.dumps(value))
            replaced = True
            break
    if not replaced:
        lines.insert(section + 1, "  HTTP_URL: {}\n".format(json.dumps(value)))

path.write_text("".join(lines), encoding="utf-8")
PY

  local updater="${ARL_DIR}/scripts/update-proxy-runtime.sh"
  [[ -f "$updater" ]] || die "仓库缺少持久化 Web/Scheduler 代理运行时脚本"
  chmod 0755 \
    "$updater" \
    "${ARL_DIR}/scripts/rollback-proxy-runtime.sh" \
    "${ARL_DIR}/scripts/compose-env.py"

  log "构建并切换带持久化 PySocks 的 Web/Scheduler 镜像"
  (
    cd "$ARL_DIR"
    ARL_BASE_IMAGE="$ARL_BASE_IMAGE" \
    ARL_PROXY_RUNTIME_IMAGE="$ARL_PROXY_RUNTIME_IMAGE" \
    ARL_HTTPS_PORT="$ARL_HTTPS_PORT" \
    bash "$updater"
  )

  wait_http "代理配置后的 ARL Web" \
    "https://127.0.0.1:${ARL_HTTPS_PORT}/api/doc" \
    "-kfsS --connect-timeout 3 --max-time 8" \
    80 || die "持久化代理运行时切换后 ARL Web 未恢复"

  ok "ARL HTTP 代理已设置：$HTTP_PROXY_URL"
  ok "Web、Scheduler 与 Worker 的 PySocks 均来自镜像构建，不再运行时 pip 安装"
}
