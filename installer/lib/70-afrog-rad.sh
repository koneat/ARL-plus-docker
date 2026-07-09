# shellcheck shell=bash

compose_env_set() {
  local key="$1"
  local value="$2"
  local tool="${ARL_DIR}/scripts/compose-env.py"
  [[ -f "$tool" ]] || die "仓库缺少 scripts/compose-env.py"
  python3 "$tool" "${ARL_DIR}/.env" set "$key" "$value"
}

compose_env_unset() {
  local key="$1"
  local tool="${ARL_DIR}/scripts/compose-env.py"
  [[ -f "$tool" ]] || die "仓库缺少 scripts/compose-env.py"
  python3 "$tool" "${ARL_DIR}/.env" unset "$key"
}

prepare_worker_runtime_env() {
  compose_env_set AFROG_VERSION "$AFROG_VERSION"
  compose_env_set RAD_VERSION "$RAD_VERSION"
  compose_env_set INSTALL_CHROMIUM "$INSTALL_CHROMIUM"
  compose_env_set REPORT_WORLD_READABLE "$REPORT_WORLD_READABLE"
  compose_env_set AFROG_CALLBACK_DOMAIN "$AFROG_CALLBACK_DOMAIN"
  compose_env_set AFROG_CALLBACK_API_URL "$AFROG_CALLBACK_API_URL"
  compose_env_set ARL_NUCLEI_TAGS "$ARL_NUCLEI_TAGS"
  compose_env_set ARL_NUCLEI_SEVERITY "$ARL_NUCLEI_SEVERITY"
  compose_env_set ARL_NUCLEI_EXCLUDE_TAGS "$ARL_NUCLEI_EXCLUDE_TAGS"
  compose_env_set ARL_NUCLEI_RATE_LIMIT "$ARL_NUCLEI_RATE_LIMIT"

  if [[ "$ENABLE_VLESS_PROXY" == "true" && "${XRAY_PROXY_HEALTHY:-false}" == "true" ]]; then
    AFROG_PROXY_URL="socks5://${DOCKER_GATEWAY}:${XRAY_SOCKS_PORT}"
    export AFROG_PROXY_URL
    compose_env_set AFROG_PROXY_URL "$AFROG_PROXY_URL"
    ok "Afrog 将使用已验证的 VLESS 出口：$AFROG_PROXY_URL"
  else
    AFROG_PROXY_URL=''
    export AFROG_PROXY_URL
    compose_env_unset AFROG_PROXY_URL
    if [[ "$ENABLE_VLESS_PROXY" == "true" ]]; then
      warn "VLESS 出口未通过健康检查，Afrog 不强制使用失效代理"
    fi
  fi
}

install_worker_variant() {
  prepare_worker_runtime_env

  if [[ "$ENABLE_WORKER_EXTENSIONS" == "true" ]]; then
    require_amd64
    local updater="${ARL_DIR}/scripts/update-enhanced-worker.sh"
    [[ -f "$updater" ]] || die "仓库缺少持久化增强 Worker 更新脚本"
    chmod 0755 \
      "$updater" \
      "${ARL_DIR}/scripts/rollback-enhanced-worker.sh" \
      "${ARL_DIR}/scripts/compose-env.py"
    log "构建并切换持久化增强 Worker：智能泛解析、Nuclei、Afrog、RAD、Chromium、libpcap、PySocks 与高价值字典"
    (
      cd "$ARL_DIR"
      ARL_BASE_IMAGE="$ARL_BASE_IMAGE" \
      ARL_ENHANCED_WORKER_IMAGE="$ARL_ENHANCED_WORKER_IMAGE" \
      AFROG_VERSION="$AFROG_VERSION" \
      RAD_VERSION="$RAD_VERSION" \
      INSTALL_CHROMIUM="$INSTALL_CHROMIUM" \
      bash "$updater"
    )
    ok "持久化增强 Worker 已启用；容器重建后工具不会丢失"
    return 0
  fi

  if [[ "$ENABLE_SMART_WILDCARD" == "true" ]]; then
    install_smart_wildcard
    return 0
  fi

  if [[ "$ENABLE_ARL_HTTP_PROXY" == "true" ]]; then
    die "启用 ARL HTTP 代理时，必须启用 ENABLE_SMART_WILDCARD 或 ENABLE_WORKER_EXTENSIONS，以提供持久化 PySocks Worker"
  fi

  ok "使用仓库基础 Worker，不安装额外扩展"
}

# 兼容旧安装器函数名；实际实现已改为持久化自定义镜像。
install_afrog_and_rad() {
  install_worker_variant
}
