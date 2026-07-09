# shellcheck shell=bash

validate_vless_nodes() {
  [[ "$ENABLE_VLESS_PROXY" == "true" ]] || return 0
  [[ -f "$VLESS_NODES_FILE" ]] ||
    die "启用 VLESS 时必须先在本机创建节点文件：$VLESS_NODES_FILE"
  if [[ "$CHECK_ONLY" != "true" ]]; then
    chmod 0600 "$VLESS_NODES_FILE"
  fi

  python3 - "$VLESS_NODES_FILE" <<'PY'
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import sys

path = Path(sys.argv[1])
nodes = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
if not nodes:
    raise SystemExit("VLESS 节点列表为空")

seen = set()
for number, node in enumerate(nodes, 1):
    parsed = urlsplit(node)
    query = parse_qs(parsed.query)
    if parsed.scheme != "vless":
        raise SystemExit(f"第 {number} 条不是 VLESS 链接")
    if not parsed.username or not parsed.hostname or not parsed.port:
        raise SystemExit(f"第 {number} 条缺少 UUID、地址或端口")
    if query.get("type", [""])[0] != "ws":
        raise SystemExit(f"第 {number} 条不是 WebSocket 节点")
    if not query.get("host", [""])[0] or not query.get("path", [""])[0]:
        raise SystemExit(f"第 {number} 条缺少 host 或 path")
    identity = (parsed.username, parsed.hostname, parsed.port, query["host"][0], query["path"][0])
    if identity in seen:
        raise SystemExit(f"第 {number} 条为重复节点")
    seen.add(identity)

print(f"[OK] VLESS 节点校验通过：{len(nodes)} 条")
PY
}
detect_docker_gateway() {
  local i
  DOCKER_GATEWAY=""
  for i in $(seq 1 60); do
    DOCKER_GATEWAY="$(
      docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{println $v.Gateway}}{{end}}' \
        arl_worker 2>/dev/null | awk 'NF {print; exit}'
    )"
    [[ -n "$DOCKER_GATEWAY" ]] && break
    sleep 2
  done

  if [[ -z "$DOCKER_GATEWAY" ]]; then
    DOCKER_GATEWAY="$(ip -4 addr show docker0 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')"
  fi

  [[ -n "$DOCKER_GATEWAY" ]] || die "无法获取 ARL Docker 网络网关"
  export DOCKER_GATEWAY
  ok "ARL Docker 网关：$DOCKER_GATEWAY"
}

github_api_curl() {
  local url="$1"
  if [[ -n "$GITHUB_TOKEN" ]]; then
    curl -fsSL --retry 5 --retry-all-errors \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url"
  else
    curl -fsSL --retry 5 --retry-all-errors \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url"
  fi
}

download_release_asset() {
  local repo="$1"
  local tag="$2"
  local asset_regex="$3"
  local output="$4"
  local api_url download_url

  api_url="https://api.github.com/repos/${repo}/releases/tags/${tag}"
  download_url="$(
    github_api_curl "$api_url" |
      jq -r --arg regex "$asset_regex" \
        '.assets[] | select(.name | test($regex)) | .browser_download_url' |
      head -n 1
  )"

  [[ -n "$download_url" && "$download_url" != "null" ]] ||
    die "没有找到 ${repo} ${tag} 对应资源：${asset_regex}"

  curl -fL --retry 5 --retry-all-errors --connect-timeout 20 --max-time 1200 \
    "$download_url" -o "$output"
}

require_amd64() {
  case "$(uname -m)" in
    x86_64|amd64) ;;
    *) die "当前完整脚本内置的是 Linux AMD64 工具包，检测到架构：$(uname -m)" ;;
  esac
}
