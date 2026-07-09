# shellcheck shell=bash

validate_compose() {
  cd "$ARL_DIR"
  docker compose config >/dev/null
  ok "docker compose config 校验通过"
}

deploy_services() {
  cd "$ARL_DIR"
  docker volume inspect arl_db >/dev/null 2>&1 || docker volume create arl_db >/dev/null

  log "拉取 ARL 依赖镜像"
  docker compose pull web worker scheduler mongodb rabbitmq

  log "构建 MCP 镜像"
  docker compose build --pull mcp-local mcp

  log "启动 ARL、RabbitMQ、MongoDB、Worker、Scheduler 与 MCP"
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
    # curl_args 是脚本内部固定值，不接受用户输入
    # shellcheck disable=SC2086
    if curl $curl_args "$url" >/dev/null 2>&1; then
      ok "$name 可访问"
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
INSTALL_SCRIPT=/root/install-arl-full.sh
COMPOSE_ENV=${ARL_DIR}/.env
EOF
  chmod 600 "$credentials_file"

  ok "第一阶段部署完成"
  echo
  echo "ARL:      https://${access_host}:${ARL_HTTPS_PORT}/"
  echo "MCP 本机: http://${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}/mcp（默认免 Token）"
  echo "MCP 外部: http://${MCP_EXTERNAL_BIND_IP}:${MCP_EXTERNAL_PORT}/mcp（强制 Token）"
  echo "凭据文件：${credentials_file}"
  echo "完整日志：${LOG_FILE}"
}
