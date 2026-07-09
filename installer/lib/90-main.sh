static_validate_installer() {
  local leaked='false' file

  while IFS= read -r -d '' file; do
    bash -n "$file"
  done < <(find "$INSTALLER_DIR" -type f -name '*.sh' -print0)

  for required in REPO_URL REPO_BRANCH ARL_DIR ARL_MONGO_DB MCP_LOCAL_BIND_IP MCP_EXTERNAL_BIND_IP; do
    [[ -n "${!required:-}" ]] || die "缺少参数：$required"
  done

  if grep -R -E -q \
      --include='*.sh' \
      'mongodb\+srv://[^[:space:]]+:[^[:space:]]+@|vless:[/][/][0-9a-fA-F-]{20,}' \
      "$INSTALLER_DIR"; then
    leaked='true'
  fi
  [[ "$leaked" == 'false' ]] || die '公开部署引擎中检测到疑似 Mongo 凭据或 VLESS 节点'

  # 安装器默认值必须指向克隆后的本仓库文件，不能重新引入第三方 Raw 依赖。
  [[ "$API_DICT_URL" == file://*'/wordlists/vendor/api-endpoints.txt' ]] ||
    die "API_DICT_URL 必须默认使用仓库内置字典：$API_DICT_URL"
  [[ "$FUZZ_DICT_URL" == file://*'/wordlists/vendor/raft-small-files.txt' ]] ||
    die "FUZZ_DICT_URL 必须默认使用仓库内置字典：$FUZZ_DICT_URL"
  [[ "$DOMAIN_DICT_URL" == file://*'/wordlists/vendor/subdomains-main.txt' ]] ||
    die "DOMAIN_DICT_URL 必须默认使用仓库内置字典：$DOMAIN_DICT_URL"

  validate_env
  if [[ "$ENABLE_VLESS_PROXY" == 'true' ]]; then
    validate_vless_nodes
  fi
  ok '部署引擎静态检查通过；未执行安装或系统修改'
}

main() {
  if [[ "$CHECK_ONLY" == "true" ]]; then
    static_validate_installer
    return 0
  fi

  require_root
  validate_env

  log "开始完整部署：ARL + MCP + 持久化 Worker + VLESS/Xray + 独立 Scanner"
  install_base_packages
  install_docker_if_needed
  configure_firewall
  check_dns
  clone_or_update_repo
  prepare_vendored_wordlists
  prepare_config
  prepare_compose_file
  prepare_compose_env
  prepare_reports
  validate_compose
  deploy_services
  verify_services

  # 先取得容器网络和代理健康状态，再构建 Worker，保证 Afrog 代理参数可靠。
  detect_docker_gateway
  install_xray_core
  install_worker_variant

  # Worker 已带持久化 PySocks 后，再写入 ARL 代理并切换 Web/Scheduler 运行时。
  set_arl_http_proxy
  install_chaitin_xray
  prepare_scanner_stack
  verify_full_stack
}
