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
  chmod 0750 "$CHAITIN_XRAY_DIR" "$REPORT_ROOT/xray" "$REPORT_ROOT/xray/history"
  chmod 0755 "$CHAITIN_XRAY_DIR/xray"
  chmod 0640 "$CHAITIN_XRAY_DIR"/ca.* 2>/dev/null || true

  cat > /usr/local/sbin/arl-xray-rotate-report.sh <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

REPORT_DIR='${REPORT_ROOT}/xray'
CURRENT_REPORT="\${REPORT_DIR}/proxy.html"
ARCHIVE_DIR="\${REPORT_DIR}/history"

mkdir -p "\$REPORT_DIR" "\$ARCHIVE_DIR"

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

[Service]
Type=simple
User=arl-xray
Group=arl-xray
WorkingDirectory=${CHAITIN_XRAY_DIR}
UMask=0027
ExecStartPre=/usr/local/sbin/arl-xray-rotate-report.sh
ExecStart=${CHAITIN_XRAY_DIR}/xray webscan --listen ${DOCKER_GATEWAY}:${CHAITIN_XRAY_PORT} --html-output ${REPORT_ROOT}/xray/proxy.html
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=120
StartLimitBurst=10
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
  systemctl enable --now arl-chaitin-xray.service

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

  ok "长亭 xray Webscan 代理：http://${DOCKER_GATEWAY}:${CHAITIN_XRAY_PORT}"
  ok "当前报告：${REPORT_ROOT}/xray/proxy.html"
  ok "历史报告：${REPORT_ROOT}/xray/history/"
  rm -rf "$tmp_dir"
}
