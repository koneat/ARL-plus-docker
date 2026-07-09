prepare_chaitin_xray_config() {
  local config
  local -a required_configs=(
    "${CHAITIN_XRAY_DIR}/xray.yaml"
    "${CHAITIN_XRAY_DIR}/module.xray.yaml"
    "${CHAITIN_XRAY_DIR}/plugin.xray.yaml"
  )
  local missing='false'

  for config in "${required_configs[@]}"; do
    if [[ ! -s "$config" ]]; then
      missing='true'
      break
    fi
  done

  if [[ "$missing" == 'true' ]]; then
    log '首次运行长亭 xray 以生成默认配置；1.9.11 生成配置后会主动退出，这是正常行为'
    (
      cd "$CHAITIN_XRAY_DIR"
      set +e
      timeout 30s runuser -u arl-xray -- \
        ./xray webscan \
        --listen "${DOCKER_GATEWAY}:${CHAITIN_XRAY_PORT}" \
        --html-output "${REPORT_ROOT}/xray/proxy.html"
      rc=$?
      set -e
      case "$rc" in
        0|1|124) ;;
        *) warn "长亭 xray 首次配置生成命令退出码：$rc；继续按配置文件结果判断" ;;
      esac
    )
  fi

  for config in "${required_configs[@]}"; do
    [[ -s "$config" ]] || die "长亭 xray 首次运行后仍未生成配置：$config"
  done

  chown arl-xray:arl-xray "${required_configs[@]}"
  chmod 0640 "${required_configs[@]}"
  ok '长亭 xray 默认配置已准备完成'
}

install_chaitin_xray() {
  [[ "$ENABLE_CHAITIN_XRAY" == "true" ]] || {
    warn "已关闭长亭 xray Webscan"
    return 0
  }

  require_amd64

  local tmp_dir archive binary
  tmp_dir="$(mktemp -d)"
  archive="${tmp_dir}/chaitin-xray.zip"

  log "下载长亭 xray ${CHAITIN_XRAY_VERSION}"
  download_release_asset \
    "chaitin/xray" "$CHAITIN_XRAY_VERSION" '^xray_linux_amd64\.zip$' "$archive"

  unzip -oq "$archive" -d "$tmp_dir/unpacked"
  binary="$(find "$tmp_dir/unpacked" -type f \( -name xray_linux_amd64 -o -name xray \) | head -n 1)"
  [[ -n "$binary" ]] || die "长亭 xray 压缩包内没有找到主程序"

  install -d -m 0755 "$CHAITIN_XRAY_DIR"
  install -m 0755 "$binary" "$CHAITIN_XRAY_DIR/xray"

  if ! id arl-xray >/dev/null 2>&1; then
    useradd \
      --system \
      --home-dir "$CHAITIN_XRAY_DIR" \
      --shell /usr/sbin/nologin \
      arl-xray
  fi

  # REPORT_ROOT 由 root 创建并保持不可列目录，但必须允许 arl-xray 穿过父目录。
  # 具体 xray 子目录仍由专用账户独占，报告内容不会因此全局可读。
  install -d -o root -g root -m 0711 "$REPORT_ROOT"
  install -d -o arl-xray -g arl-xray -m 0750 \
    "$REPORT_ROOT/xray" \
    "$REPORT_ROOT/xray/history"

  if [[ ! -s "$CHAITIN_XRAY_DIR/ca.crt" || ! -s "$CHAITIN_XRAY_DIR/ca.key" ]]; then
    (
      cd "$CHAITIN_XRAY_DIR"
      ./xray genca
    )
  fi

  chown -R arl-xray:arl-xray "$CHAITIN_XRAY_DIR" "$REPORT_ROOT/xray"
  chmod 0711 "$REPORT_ROOT"
  chmod 0750 "$CHAITIN_XRAY_DIR" "$REPORT_ROOT/xray" "$REPORT_ROOT/xray/history"
  chmod 0755 "$CHAITIN_XRAY_DIR/xray"
  chmod 0640 "$CHAITIN_XRAY_DIR"/ca.* 2>/dev/null || true

  prepare_chaitin_xray_config

  cat > /usr/local/sbin/arl-xray-rotate-report.sh <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

REPORT_DIR='${REPORT_ROOT}/xray'
CURRENT_REPORT="\${REPORT_DIR}/proxy.html"
ARCHIVE_DIR="\${REPORT_DIR}/history"

test -d "\$REPORT_DIR"
test -d "\$ARCHIVE_DIR"
test -w "\$REPORT_DIR"
test -w "\$ARCHIVE_DIR"

if [[ -e "\$CURRENT_REPORT" ]]; then
  STAMP="\$(date '+%Y%m%d-%H%M%S')-\$$"
  DEST="\${ARCHIVE_DIR}/proxy-\${STAMP}.html"

  if [[ -s "\$CURRENT_REPORT" ]]; then
    mv -- "\$CURRENT_REPORT" "\$DEST"
    echo "[OK] 旧 xray 报告已归档：\$DEST"
  else
    rm -f -- "\$CURRENT_REPORT"
    echo "[OK] 已删除空的旧 xray 报告"
  fi
fi

find "\$ARCHIVE_DIR" \
  -type f \
  -name 'proxy-*.html' \
  -mtime +30 \
  -delete 2>/dev/null || true
EOF

  chmod 0755 /usr/local/sbin/arl-xray-rotate-report.sh

  systemctl stop arl-chaitin-xray.service 2>/dev/null || true

  cat > /etc/systemd/system/arl-chaitin-xray.service <<EOF
[Unit]
Description=ARL Chaitin xray Webscan
After=network-online.target docker.service arl-vless-xray.service
Wants=network-online.target
Requires=docker.service
StartLimitIntervalSec=120
StartLimitBurst=10

[Service]
Type=simple
User=arl-xray
Group=arl-xray
WorkingDirectory=${CHAITIN_XRAY_DIR}
UMask=0027
ExecStartPre=/usr/bin/test -x ${REPORT_ROOT}
ExecStartPre=/usr/bin/test -w ${REPORT_ROOT}/xray
ExecStartPre=/usr/bin/test -s ${CHAITIN_XRAY_DIR}/xray.yaml
ExecStartPre=/usr/bin/test -s ${CHAITIN_XRAY_DIR}/module.xray.yaml
ExecStartPre=/usr/bin/test -s ${CHAITIN_XRAY_DIR}/plugin.xray.yaml
ExecStartPre=/usr/local/sbin/arl-xray-rotate-report.sh
ExecStart=${CHAITIN_XRAY_DIR}/xray webscan --listen ${DOCKER_GATEWAY}:${CHAITIN_XRAY_PORT} --html-output ${REPORT_ROOT}/xray/proxy.html
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${REPORT_ROOT}/xray ${CHAITIN_XRAY_DIR}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl reset-failed arl-chaitin-xray.service 2>/dev/null || true
  systemctl enable arl-chaitin-xray.service

  if ! systemctl start arl-chaitin-xray.service; then
    warn '长亭 xray 第一次 systemd 启动失败，重置状态后自动重试一次'
    systemctl reset-failed arl-chaitin-xray.service 2>/dev/null || true
    sleep 1
    if ! systemctl start arl-chaitin-xray.service; then
      systemctl status arl-chaitin-xray.service --no-pager || true
      journalctl -u arl-chaitin-xray.service -n 120 --no-pager || true
      die '长亭 xray 重试后仍然启动失败'
    fi
  fi

  local i
  for i in $(seq 1 45); do
    if nc -z -w 2 "$DOCKER_GATEWAY" "$CHAITIN_XRAY_PORT" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  if ! nc -z -w 2 "$DOCKER_GATEWAY" "$CHAITIN_XRAY_PORT" >/dev/null 2>&1; then
    systemctl status arl-chaitin-xray.service --no-pager || true
    journalctl -u arl-chaitin-xray.service -n 120 --no-pager || true
    die "长亭 xray 没有监听 ${DOCKER_GATEWAY}:${CHAITIN_XRAY_PORT}"
  fi

  ok "长亭 xray Webscan 已由 systemd 后台常驻：http://${DOCKER_GATEWAY}:${CHAITIN_XRAY_PORT}"
  ok "当前报告：${REPORT_ROOT}/xray/proxy.html"
  ok "历史报告：${REPORT_ROOT}/xray/history/"
  rm -rf "$tmp_dir"
}
