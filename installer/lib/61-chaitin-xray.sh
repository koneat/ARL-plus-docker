prepare_chaitin_xray_config() {
  local config
  local -a required_configs=(
    "${CHAITIN_XRAY_DIR}/xray.yaml"
    "${CHAITIN_XRAY_DIR}/module.xray.yaml"
    "${CHAITIN_XRAY_DIR}/plugin.xray.yaml"
    "${CHAITIN_XRAY_DIR}/config.yaml"
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

disable_chaitin_xray_cors_baseline() {
  local config="${CHAITIN_XRAY_DIR}/config.yaml"

  [[ -s "$config" ]] || die "长亭 xray 漏洞扫描配置不存在：$config"

  python3 - "$config" <<'PY'
from pathlib import Path
import re
import shutil
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
lines = text.splitlines()
trailing_newline = text.endswith('\n')


def indentation(line):
    return len(line) - len(line.lstrip(' '))


plugins_index = next(
    (index for index, line in enumerate(lines) if re.match(r'^plugins:\s*(?:#.*)?$', line)),
    None,
)
if plugins_index is None:
    raise SystemExit('config.yaml 中未找到 plugins 配置段')

baseline_index = None
for index in range(plugins_index + 1, len(lines)):
    line = lines[index]
    if line.strip() and not line.lstrip().startswith('#') and indentation(line) == 0:
        break
    if re.match(r'^\s+baseline:\s*(?:#.*)?$', line):
        baseline_index = index
        break
if baseline_index is None:
    raise SystemExit('config.yaml 中未找到 plugins.baseline 配置段')

baseline_indent = indentation(lines[baseline_index])
baseline_end = len(lines)
for index in range(baseline_index + 1, len(lines)):
    line = lines[index]
    if line.strip() and not line.lstrip().startswith('#') and indentation(line) <= baseline_indent:
        baseline_end = index
        break

key_pattern = re.compile(
    r'^(\s*detect_cors_header_config:\s*)(true|false)(\s*(?:#.*)?)$'
)
key_index = None
changed = False
for index in range(baseline_index + 1, baseline_end):
    match = key_pattern.match(lines[index])
    if not match:
        continue
    key_index = index
    replacement = f'{match.group(1)}false{match.group(3)}'
    if replacement != lines[index]:
        lines[index] = replacement
        changed = True
    break

if key_index is None:
    insert_at = baseline_index + 1
    for index in range(baseline_index + 1, baseline_end):
        if re.match(r'^\s*enabled:\s*(?:true|false)\b', lines[index]):
            insert_at = index + 1
            break
    lines.insert(
        insert_at,
        ' ' * (baseline_indent + 2)
        + 'detect_cors_header_config: false  # ARL: 禁用 baseline CORS 噪声规则',
    )
    changed = True

result = '\n'.join(lines) + ('\n' if trailing_newline else '')
if changed:
    backup = path.with_name(path.name + '.pre-arl-cors-disable.bak')
    if not backup.exists():
        shutil.copy2(path, backup)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(result, encoding='utf-8')
    temporary.chmod(path.stat().st_mode)
    temporary.replace(path)

updated = path.read_text(encoding='utf-8')
if not re.search(r'^\s*detect_cors_header_config:\s*false\b', updated, re.MULTILINE):
    raise SystemExit('未能关闭 plugins.baseline.detect_cors_header_config')
PY

  chown arl-xray:arl-xray "$config"
  chmod 0640 "$config"
  ok '已关闭长亭 xray baseline CORS 检查（包含 any-origin-with-credential）'
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

  install -d -o root -g root -m 0755 "$REPORT_ROOT"
  install -d -o arl-xray -g arl-xray -m 0755 \
    "$REPORT_ROOT/xray" \
    "$REPORT_ROOT/xray/history"

  if [[ ! -s "$CHAITIN_XRAY_DIR/ca.crt" || ! -s "$CHAITIN_XRAY_DIR/ca.key" ]]; then
    (
      cd "$CHAITIN_XRAY_DIR"
      ./xray genca
    )
  fi

  chown -R arl-xray:arl-xray "$CHAITIN_XRAY_DIR" "$REPORT_ROOT/xray"
  chmod 0755 "$REPORT_ROOT" "$REPORT_ROOT/xray" "$REPORT_ROOT/xray/history"
  chmod 0750 "$CHAITIN_XRAY_DIR"
  chmod 0755 "$CHAITIN_XRAY_DIR/xray"
  chmod 0640 "$CHAITIN_XRAY_DIR"/ca.* 2>/dev/null || true
  find "$REPORT_ROOT/xray" -type f -name '*.html' -exec chmod 0644 {} + 2>/dev/null || true

  prepare_chaitin_xray_config
  disable_chaitin_xray_cors_baseline

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

chmod 0755 "\$REPORT_DIR" "\$ARCHIVE_DIR"

if [[ -e "\$CURRENT_REPORT" ]]; then
  STAMP="\$(date '+%Y%m%d-%H%M%S')-\$$"
  DEST="\${ARCHIVE_DIR}/proxy-\${STAMP}.html"

  if [[ -s "\$CURRENT_REPORT" ]]; then
    chmod 0644 "\$CURRENT_REPORT" 2>/dev/null || true
    mv -- "\$CURRENT_REPORT" "\$DEST"
    chmod 0644 "\$DEST"
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
# 报告通过 ARL Web 容器发布；0022 确保新生成 HTML 为 0644，避免跨容器 403。
UMask=0022
ExecStartPre=/usr/bin/test -x ${REPORT_ROOT}
ExecStartPre=/usr/bin/test -w ${REPORT_ROOT}/xray
ExecStartPre=/usr/bin/test -s ${CHAITIN_XRAY_DIR}/xray.yaml
ExecStartPre=/usr/bin/test -s ${CHAITIN_XRAY_DIR}/module.xray.yaml
ExecStartPre=/usr/bin/test -s ${CHAITIN_XRAY_DIR}/plugin.xray.yaml
ExecStartPre=/usr/bin/test -s ${CHAITIN_XRAY_DIR}/config.yaml
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
