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

  log "开始完整部署：ARL + MCP + VLESS + Xray + Afrog"
  install_base_packages
  install_docker_if_needed
  configure_firewall
  check_dns
  clone_or_update_repo
  prepare_config
  prepare_compose_file
  prepare_compose_env
  prepare_reports
  validate_compose
  deploy_services
  verify_services
  install_smart_wildcard
  detect_docker_gateway
  install_xray_core
  set_arl_http_proxy
  install_chaitin_xray
  install_afrog_and_rad
  prepare_scanner_stack
  verify_full_stack
}
