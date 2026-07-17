# shellcheck shell=bash

install_smart_wildcard() {
  [[ "$ENABLE_SMART_WILDCARD" == "true" ]] || {
    ok "未启用智能泛解析 Worker"
    return 0
  }

  local updater="${ARL_DIR}/scripts/update-smart-wildcard.sh"
  local overlay="${ARL_DIR}/docker-compose.smart-wildcard.yml"
  [[ -f "$updater" && -f "$overlay" ]] ||
    die "仓库缺少智能泛解析更新组件，请确认 main 分支已更新"

  log "构建并安全切换智能泛解析 Worker；失败时由仓库脚本自动回滚"
  chmod 0755 "$updater"
  (
    cd "$ARL_DIR"
    bash "$updater"
  )
  ok "智能泛解析 Worker 已启用"
}

prepare_scanner_stack() {
  [[ "$ENABLE_SCANNER_STACK" == "true" ]] || {
    ok "未启用独立实战扫描链"
    return 0
  }

  local compose_file="${ARL_DIR}/docker-compose.scanner.yml"
  [[ -f "$compose_file" && -f "${ARL_DIR}/scripts/scan-enhanced.sh" ]] ||
    die "仓库缺少独立 Scanner 组件，请确认 main 分支已更新"

  install -d -m 0755 \
    "${ARL_DIR}/scan-results" \
    "${ARL_DIR}/scanner-cache/config" \
    "${ARL_DIR}/scanner-cache/nuclei-templates" \
    "${ARL_DIR}/scanner-pocs/nuclei" \
    "${ARL_DIR}/scanner-pocs/afrog"
  install -d -m 0700 "${ARL_DIR}/scanner-secrets"

  if [[ -n "$FOFA_EMAIL$FOFA_KEY$HUNTER_API_KEY$QUAKE_TOKEN$SHODAN_API_KEY$ZOOMEYE_API_KEY" ]]; then
    export UNCOVER_CONFIG_PATH="${ARL_DIR}/scanner-secrets/uncover-provider.yaml"
    python3 <<'PY'
from __future__ import annotations

import os
from pathlib import Path
import yaml

config = {}
fofa_email = os.environ.get("FOFA_EMAIL", "")
fofa_key = os.environ.get("FOFA_KEY", "")
if fofa_email and fofa_key:
    config["fofa"] = [f"{fofa_email}:{fofa_key}"]
for env_name, key in (
    ("HUNTER_API_KEY", "hunter"),
    ("QUAKE_TOKEN", "quake"),
    ("SHODAN_API_KEY", "shodan"),
    ("ZOOMEYE_API_KEY", "zoomeye"),
):
    value = os.environ.get(env_name, "")
    if value:
        config[key] = [value]

path = Path(os.environ["UNCOVER_CONFIG_PATH"])
path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
PY
    chmod 0600 "$UNCOVER_CONFIG_PATH"
    ok "已从本机配置生成 Scanner/Uncover 凭据文件"
  else
    warn "未配置外部搜索引擎凭据，Scanner 仍可运行，但 Uncover 资产聚合会跳过无凭据引擎"
  fi

  (
    cd "$ARL_DIR"
    docker compose -f docker-compose.scanner.yml --profile scanner config >/dev/null
    local scanner_image
    scanner_image="${ARL_SCANNER_V2_IMAGE:-arl-plus-scanner:2026.07-v2-control}"
    docker image inspect "$scanner_image" >/dev/null 2>&1 ||
      die "独立 Scanner 复用镜像不存在：$scanner_image"
    ok "独立 Scanner 复用已构建的 Scanner V2 镜像：$scanner_image"
  )
  chmod 0755 "${ARL_DIR}/scripts/scan-enhanced.sh"
  ok "独立实战扫描链已准备完成"
}

verify_full_stack() {
  local access_host credentials_file node_count socks5_url chaitin_url
  access_host="$ARL_BIND_IP"
  if [[ "$access_host" == "0.0.0.0" ]]; then
    access_host="$(
      hostname -I 2>/dev/null |
        awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./){print $i; exit}}'
    )"
    access_host="${access_host:-服务器IP}"
  fi

  ARL_REPORT_ROOT="$REPORT_ROOT" /usr/local/bin/arl-report-index
  node_count='0'
  socks5_url='disabled'
  chaitin_url='disabled'
  if [[ "$ENABLE_VLESS_PROXY" == "true" ]]; then
    node_count="$(grep -c '^vless:[/][/]' "$VLESS_NODES_FILE" 2>/dev/null || true)"
    socks5_url="socks5://${DOCKER_GATEWAY}:${XRAY_SOCKS_PORT}"
  fi
  if [[ "$ENABLE_CHAITIN_XRAY" == "true" ]]; then
    chaitin_url="http://${DOCKER_GATEWAY}:${CHAITIN_XRAY_PORT}"
  fi

  credentials_file="/root/arl-deploy-credentials.txt"
  cat >> "$credentials_file" <<EOF

SOCKS5_URL=${socks5_url}
VLESS_NODE_COUNT=${node_count}
VLESS_NODES_FILE=${VLESS_NODES_FILE}
CHAITIN_XRAY_PROXY=${chaitin_url}
REPORT_URL=https://${access_host}:${ARL_HTTPS_PORT}/report/
XRAY_REPORT=https://${access_host}:${ARL_HTTPS_PORT}/report/xray/proxy.html
AFROG_REPORTS=https://${access_host}:${ARL_HTTPS_PORT}/report/afrog/
AFROG_COMMAND=afrog-arl -t https://目标
SCANNER_COMMAND=cd ${ARL_DIR} && bash scripts/scan-enhanced.sh targets.txt standard
EOF
  chmod 0600 "$credentials_file"

  echo
  echo "==================== 最终状态 ===================="
  docker compose -f "${ARL_DIR}/docker-compose.yml" ps
  if [[ "$ENABLE_VLESS_PROXY" == "true" ]]; then
    systemctl --no-pager --full status arl-vless-xray.service 2>/dev/null |
      sed -n '1,8p' || true
  fi
  if [[ "$ENABLE_CHAITIN_XRAY" == "true" ]]; then
    systemctl --no-pager --full status arl-chaitin-xray.service 2>/dev/null |
      sed -n '1,8p' || true
  fi
  echo
  echo "ARL:            https://${access_host}:${ARL_HTTPS_PORT}/"
  echo "MCP 本机:       http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/mcp（默认免 Token）"
  echo "MCP 外部:       http://${MCP_EXTERNAL_BIND_IP}:${MCP_EXTERNAL_PORT}/mcp（强制 Token）"
  echo "SOCKS5:         ${socks5_url}"
  echo "长亭 xray:      ${chaitin_url}"
  echo "扫描报告:       https://${access_host}:${ARL_HTTPS_PORT}/report/"
  echo "VLESS 节点数:   ${node_count}"
  echo "凭据文件:       ${credentials_file}"
  echo "独立 Scanner:   cd ${ARL_DIR} && bash scripts/scan-enhanced.sh targets.txt standard"
  echo "安装日志:       ${LOG_FILE}"
  echo "=================================================="
}
