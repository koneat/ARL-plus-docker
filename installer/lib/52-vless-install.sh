install_xray_core() {
  [[ "$ENABLE_VLESS_PROXY" == "true" ]] || {
    warn "已关闭 VLESS/Xray-core 安装"
    return 0
  }

  require_amd64
  validate_vless_nodes
  XRAY_PROXY_HEALTHY='false'
  export XRAY_PROXY_HEALTHY

  local tmp_dir archive binary
  tmp_dir="$(mktemp -d)"
  archive="${tmp_dir}/xray-core.zip"

  log "下载 Xray-core ${XRAY_CORE_VERSION}"
  download_release_asset \
    "XTLS/Xray-core" "$XRAY_CORE_VERSION" '^Xray-linux-64\.zip$' "$archive"

  unzip -oq "$archive" -d "$tmp_dir/unpacked"
  binary="$(find "$tmp_dir/unpacked" -type f -name xray -perm /111 | head -n 1)"
  [[ -n "$binary" ]] || die "Xray-core 压缩包内没有找到 xray"

  install -m 0755 "$binary" /usr/local/bin/xray-core
  install -d -m 0755 /usr/local/share/xray-core
  [[ -f "$tmp_dir/unpacked/geoip.dat" ]] &&
    install -m 0644 "$tmp_dir/unpacked/geoip.dat" /usr/local/share/xray-core/geoip.dat
  [[ -f "$tmp_dir/unpacked/geosite.dat" ]] &&
    install -m 0644 "$tmp_dir/unpacked/geosite.dat" /usr/local/share/xray-core/geosite.dat

  generate_xray_core_config

  XRAY_LOCATION_ASSET=/usr/local/share/xray-core \
    /usr/local/bin/xray-core run -test -config "$XRAY_CORE_CONFIG"

  cat > /etc/systemd/system/arl-vless-xray.service <<EOF
[Unit]
Description=ARL VLESS Xray-core SOCKS5 Proxy
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=nobody
Group=nogroup
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray-core
ExecStart=/usr/local/bin/xray-core run -config ${XRAY_CORE_CONFIG}
Restart=always
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now arl-vless-xray.service

  local i
  for i in $(seq 1 30); do
    if nc -z -w 2 "$DOCKER_GATEWAY" "$XRAY_SOCKS_PORT" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  if ! nc -z -w 2 "$DOCKER_GATEWAY" "$XRAY_SOCKS_PORT" >/dev/null 2>&1; then
    systemctl status arl-vless-xray.service --no-pager || true
    journalctl -u arl-vless-xray.service -n 100 --no-pager || true
    die "Xray-core SOCKS5 没有监听 ${DOCKER_GATEWAY}:${XRAY_SOCKS_PORT}"
  fi

  ok "Xray-core SOCKS5：socks5://${DOCKER_GATEWAY}:${XRAY_SOCKS_PORT}"

  local proxy_ip
  if proxy_ip="$(
    curl -fsS --connect-timeout 10 --max-time 35 \
      --socks5-hostname "${DOCKER_GATEWAY}:${XRAY_SOCKS_PORT}" \
      "$XRAY_PROXY_TEST_URL" 2>/dev/null
  )"; then
    XRAY_PROXY_HEALTHY='true'
    export XRAY_PROXY_HEALTHY
    ok "VLESS 出口验证成功：${proxy_ip//$'\n'/ }"
  else
    warn "Xray-core 服务正常，但当前节点无法访问测试地址；节点可能失效或网络被限制"
  fi

  rm -rf "$tmp_dir"
}
