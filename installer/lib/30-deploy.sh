# shellcheck shell=bash

validate_compose() {
  cd "$ARL_DIR"
  docker compose config >/dev/null
  ok "docker compose config 校验通过"
}

clear_missing_local_image_selection() {
  local key="$1"
  local env_file="${ARL_DIR}/.env"
  local env_tool="${ARL_DIR}/scripts/compose-env.py"
  local image=''

  [[ -f "$env_tool" ]] || return 0
  if python3 "$env_tool" "$env_file" has "$key"; then
    image="$(python3 "$env_tool" "$env_file" get "$key")"
    if [[ -n "$image" ]] && ! docker image inspect "$image" >/dev/null 2>&1; then
      warn "${key} 指向的本机镜像不存在：${image}；本次先使用基础镜像，后续阶段会重新构建"
      python3 "$env_tool" "$env_file" unset "$key"
    fi
  fi
}

deploy_services() {
  cd "$ARL_DIR"
  docker volume inspect arl_db >/dev/null 2>&1 || docker volume create arl_db >/dev/null

  clear_missing_local_image_selection ARL_WEB_IMAGE
  clear_missing_local_image_selection ARL_WORKER_IMAGE
  clear_missing_local_image_selection ARL_SCHEDULER_IMAGE

  local scanner_report_dir
  scanner_report_dir="${REPORT_ROOT}/scanner"

  mkdir -p \
    "$scanner_report_dir" \
    scanner-cache/config \
    scanner-cache/nuclei-templates \
    scanner-pocs/nuclei \
    scanner-pocs/afrog \
    scanner-secrets
  chmod 0755 "$scanner_report_dir" 2>/dev/null || true
  chmod 0700 scanner-secrets 2>/dev/null || true

  log "拉取基础 ARL、MongoDB 与 RabbitMQ 镜像"
  docker pull "$ARL_BASE_IMAGE"
  docker compose pull mongodb rabbitmq

  local scanner_image env_tool
  scanner_image="${ARL_SCANNER_V2_IMAGE:-arl-plus-scanner:2026.07-v2-control}"
  env_tool="${ARL_DIR}/scripts/compose-env.py"
  [[ -f "$env_tool" ]] || die "仓库缺少 scripts/compose-env.py"
  python3 "$env_tool" "${ARL_DIR}/.env" set ARL_SCANNER_V2_IMAGE "$scanner_image"

  if [[ "$BUILD_SCANNER_IMAGE" == "true" ]]; then
    log "构建 Scanner V2 镜像"
    docker compose build --pull scanner-v2
  elif docker image inspect "$scanner_image" >/dev/null 2>&1; then
    ok "BUILD_SCANNER_IMAGE=false，复用现有 Scanner V2 镜像：$scanner_image"
  else
    die "BUILD_SCANNER_IMAGE=false，但本机缺少 Scanner V2 镜像：$scanner_image"
  fi

  log "构建 MCP 镜像"
  docker compose build --pull mcp-local mcp

  log "启动 ARL、Scanner V2、RabbitMQ、MongoDB、Worker、Scheduler 与 MCP"
  docker compose up -d --remove-orphans

  ok "容器启动命令完成"
}

wait_http() {
  local name="$1"
  local url="$2"
  local curl_args="$3"
  local attempts="${4:-60}"
  local i

  for i in $(seq 1 "$attempts"); do
    # shellcheck disable=SC2086
    if curl $curl_args "$url" >/dev/null 2>&1; then
      ok "$name 可访问"
      return 0
    fi
    sleep 3
  done
  return 1
}

wait_scanner_v2() {
  local attempts="${1:-120}"
  local i
  for i in $(seq 1 "$attempts"); do
    if docker compose exec -T scanner-v2 python3 - <<'PY' >/dev/null 2>&1
import json
import urllib.request
with urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=5) as response:
    data = json.load(response)
assert data.get('status') == 'ok'
assert data.get('scanner_v2_reachable') is True
PY
    then
      ok "Scanner V2 内部 API 可访问"
      return 0
    fi
    sleep 3
  done
  return 1
}

verify_services() {
  cd "$ARL_DIR"
  docker compose ps

  wait_http "ARL Web" \
    "https://127.0.0.1:${ARL_HTTPS_PORT}/api/doc" \
    "-kfsS --connect-timeout 3 --max-time 8" \
    80 || {
      docker compose logs --tail=120 web worker scheduler rabbitmq mongodb
      die "ARL Web 未就绪"
    }

  wait_scanner_v2 120 || {
    docker compose logs --tail=200 scanner-v2
    die "Scanner V2 内部 API 未就绪"
  }

  docker compose exec -T mcp-local python - <<'PY' >/dev/null || {
import json
import urllib.request
with urllib.request.urlopen('http://scanner-v2:8090/capabilities', timeout=10) as response:
    data = json.load(response)
assert data.get('enhanced_submit_quality_upgrade') is True
assert data.get('native_restart_quality_upgrade') is False
PY
    docker compose logs --tail=120 mcp-local scanner-v2
    die "MCP 无法访问 Scanner V2"
  }
  ok "MCP 到 Scanner V2 的内部连接验证通过"

  docker compose exec -T web test -s /code/frontend/report/scanner/index.html || {
    docker compose logs --tail=120 web scanner-v2
    die "ARL Web 无法读取 Scanner V2 报告入口"
  }
  ok "Scanner V2 报告入口已挂载到 /report/scanner/index.html"

  local external_check_host health local_code external_code external_auth_code
  external_check_host="$MCP_EXTERNAL_BIND_IP"
  if [[ "$external_check_host" == "0.0.0.0" || "$external_check_host" == "::" ]]; then
    external_check_host='127.0.0.1'
  fi

  wait_http "MCP 本机入口健康检查" \
    "http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/healthz" \
    "-fsS --connect-timeout 3 --max-time 8" \
    60 || {
      docker compose logs --tail=120 mcp-local
      die "MCP 本机入口未就绪"
    }

  wait_http "MCP 外部入口健康检查" \
    "http://${external_check_host}:${MCP_EXTERNAL_PORT}/healthz" \
    "-fsS --connect-timeout 3 --max-time 8" \
    60 || {
      docker compose logs --tail=120 mcp
      die "MCP 外部入口未就绪"
    }

  health="$(curl -fsS "http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/healthz")"
  echo "$health" | jq .

  local_code="$(curl -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 8 \
    "http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/mcp")"
  if [[ "$MCP_ALLOW_LOCAL_UNAUTHENTICATED" == "true" ]]; then
    [[ "$local_code" != "401" && "$local_code" != "403" ]] ||
      die "MCP 本机入口仍要求 Token，HTTP ${local_code}"
    ok "MCP 本机入口免认证验证通过，HTTP ${local_code}"
  fi

  external_code="$(curl -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 8 \
    "http://${external_check_host}:${MCP_EXTERNAL_PORT}/mcp")"
  [[ "$external_code" == "401" ]] ||
    die "MCP 外部入口未强制 Token，期望 HTTP 401，实际 HTTP ${external_code}"
  ok "MCP 外部入口无 Token 返回 HTTP 401"

  external_auth_code="$(curl -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 8 \
    -H "Authorization: Bearer ${MCP_TOKEN}" \
    "http://${external_check_host}:${MCP_EXTERNAL_PORT}/mcp")"
  [[ "$external_auth_code" != "401" && "$external_auth_code" != "403" ]] ||
    die "MCP 外部入口使用正确 Token 仍被拒绝，HTTP ${external_auth_code}"
  ok "MCP 外部入口 Token 验证通过，HTTP ${external_auth_code}"

  local access_host credentials_file
  access_host="$ARL_BIND_IP"
  if [[ "$access_host" == "0.0.0.0" ]]; then
    access_host="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./){print $i; exit}}')"
    access_host="${access_host:-服务器IP}"
  fi

  credentials_file="/root/arl-deploy-credentials.txt"
  cat > "$credentials_file" <<EOF
ARL_URL=https://${access_host}:${ARL_HTTPS_PORT}/
ARL_API_KEY=${ARL_API_KEY}
MCP_URL=http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/mcp
MCP_LOCAL_URL=http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/mcp
MCP_EXTERNAL_URL=http://${MCP_EXTERNAL_BIND_IP}:${MCP_EXTERNAL_PORT}/mcp
MCP_TOKEN=${MCP_TOKEN}
MCP_READ_ONLY=${MCP_READ_ONLY}
MCP_ALLOW_LOCAL_UNAUTHENTICATED=${MCP_ALLOW_LOCAL_UNAUTHENTICATED}
SCANNER_V2_REPORT_URL=https://${access_host}:${ARL_HTTPS_PORT}/report/scanner/index.html
INSTALL_SCRIPT=/root/install-arl-full.sh
COMPOSE_ENV=${ARL_DIR}/.env
EOF
  chmod 600 "$credentials_file"

  ok "第一阶段部署完成"
  echo
  echo "ARL:       https://${access_host}:${ARL_HTTPS_PORT}/"
  echo "增强报告: https://${access_host}:${ARL_HTTPS_PORT}/report/scanner/index.html"
  echo "MCP 本机:  http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/mcp（默认免 Token）"
  echo "MCP 外部:  http://${MCP_EXTERNAL_BIND_IP}:${MCP_EXTERNAL_PORT}/mcp（强制 Token）"
  echo "凭据文件：${credentials_file}"
  echo "完整日志：${LOG_FILE}"
}
