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
    lines += ["\nPROXY:\n", f"  HTTP_URL: {json.dumps(value)}\n"]
else:
    replaced = False
    for i in range(section + 1, section_end):
        if re.match(r"^\s{2}HTTP_URL\s*:", lines[i]):
            lines[i] = f"  HTTP_URL: {json.dumps(value)}\n"
            replaced = True
            break
    if not replaced:
        lines.insert(section + 1, f"  HTTP_URL: {json.dumps(value)}\n")

path.write_text("".join(lines), encoding="utf-8")
PY

  log "给 ARL Web/Worker 安装 PySocks"
  docker exec arl_web sh -lc 'python3.6 -m pip install --disable-pip-version-check PySocks' ||
    die "arl_web 安装 PySocks 失败"
  docker exec arl_worker sh -lc 'python3.6 -m pip install --disable-pip-version-check PySocks' ||
    die "arl_worker 安装 PySocks 失败"

  cd "$ARL_DIR"
  docker compose restart web worker scheduler

  wait_http "代理配置后的 ARL Web" \
    "https://127.0.0.1:${ARL_HTTPS_PORT}/api/doc" \
    "-kfsS --connect-timeout 3 --max-time 8" \
    80 || die "写入代理后 ARL Web 未恢复"

  ok "ARL HTTP 代理已设置：$HTTP_PROXY_URL"
}
