# shellcheck shell=bash

install_afrog_and_rad() {
  [[ "$ENABLE_WORKER_EXTENSIONS" == "true" ]] || {
    warn "已关闭 Afrog、RAD、字典和 Worker 扩展"
    return 0
  }

  require_amd64
  local tmp_dir afrog_archive afrog_binary rad_archive rad_binary
  tmp_dir="$(mktemp -d)"

  afrog_archive="${tmp_dir}/afrog.zip"
  log "下载 Afrog ${AFROG_VERSION}"
  download_release_asset \
    "zan8in/afrog" "$AFROG_VERSION" 'linux_amd64\.zip$' "$afrog_archive"
  unzip -oq "$afrog_archive" -d "$tmp_dir/afrog"
  afrog_binary="$(find "$tmp_dir/afrog" -type f -name afrog -perm /111 | head -n 1)"
  [[ -n "$afrog_binary" ]] || die "Afrog 压缩包内没有找到 afrog"
  install -m 0755 "$afrog_binary" /usr/local/bin/afrog

  rad_archive="${tmp_dir}/rad.zip"
  log "下载 RAD ${RAD_VERSION}"
  curl -fL --retry 5 --retry-all-errors \
    "https://github.com/chaitin/rad/releases/download/${RAD_VERSION}/rad_linux_amd64.zip" \
    -o "$rad_archive"
  unzip -oq "$rad_archive" -d "$tmp_dir/rad"
  rad_binary="$(find "$tmp_dir/rad" -type f -name rad_linux_amd64 | head -n 1)"
  [[ -n "$rad_binary" ]] || die "RAD 压缩包内没有找到 rad_linux_amd64"
  install -m 0755 "$rad_binary" /usr/local/bin/rad

  local afrog_proxy_url=''
  if [[ "$ENABLE_VLESS_PROXY" == "true" ]]; then
    afrog_proxy_url="socks5://${DOCKER_GATEWAY}:${XRAY_SOCKS_PORT}"
  fi

  cat > /usr/local/bin/afrog-arl <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
REPORT_ROOT='${REPORT_ROOT}'
REPORT_WORLD_READABLE='${REPORT_WORLD_READABLE}'
PROXY_URL='${afrog_proxy_url}'
mkdir -p "\${REPORT_ROOT}/afrog"
STAMP="\$(date +%Y%m%d-%H%M%S)"
OUTPUT="\${REPORT_ROOT}/afrog/afrog-\${STAMP}.html"

if [[ "\$#" -eq 0 ]]; then
  echo "用法：afrog-arl -t https://目标"
  echo "或：  afrog-arl -T /path/targets.txt"
  exit 2
fi

args=("\$@" -o "\$OUTPUT")
if [[ -n "\$PROXY_URL" ]]; then
  args+=( -proxy "\$PROXY_URL" )
fi

set +e
/usr/local/bin/afrog "\${args[@]}"
STATUS=\$?
set -e

if [[ -s "\$OUTPUT" ]]; then
  ln -sfn "\$(basename "\$OUTPUT")" "\${REPORT_ROOT}/afrog/latest.html"
fi
ARL_REPORT_ROOT="\$REPORT_ROOT" /usr/local/bin/arl-report-index
if [[ "\${REPORT_WORLD_READABLE:-false}" == "true" ]]; then
  chmod -R a+rX "\$REPORT_ROOT"
else
  chmod 0750 "\$REPORT_ROOT" "\$REPORT_ROOT/afrog"
  chmod 0640 "\$OUTPUT" 2>/dev/null || true
fi

echo "Afrog 报告：\$OUTPUT"
exit "\$STATUS"
EOF
  chmod 0755 /usr/local/bin/afrog-arl

  HOME=/root /usr/local/bin/afrog -h >/dev/null 2>&1 || true
  configure_afrog_callback /root/.config/afrog/afrog-config.yaml

  docker cp /usr/local/bin/afrog arl_worker:/usr/local/bin/afrog
  docker cp /usr/local/bin/rad arl_worker:/usr/local/bin/rad
  docker cp /usr/local/bin/afrog-arl arl_worker:/usr/local/bin/afrog-arl
  docker cp /usr/local/bin/arl-report-index arl_worker:/usr/local/bin/arl-report-index

  docker exec arl_worker sh -lc \
    'chmod +x /usr/local/bin/afrog /usr/local/bin/rad /usr/local/bin/afrog-arl /usr/local/bin/arl-report-index'

  HOME=/root docker exec arl_worker sh -lc \
    'HOME=/root /usr/local/bin/afrog -h >/dev/null 2>&1 || true'
  docker cp arl_worker:/root/.config/afrog/afrog-config.yaml \
    "${tmp_dir}/worker-afrog-config.yaml" 2>/dev/null || true
  if [[ -f "${tmp_dir}/worker-afrog-config.yaml" ]]; then
    configure_afrog_callback "${tmp_dir}/worker-afrog-config.yaml"
    docker cp "${tmp_dir}/worker-afrog-config.yaml" \
      arl_worker:/root/.config/afrog/afrog-config.yaml
  fi

  patch_worker_packages
  patch_worker_dicts "$tmp_dir"

  cd "$ARL_DIR"
  docker compose restart worker
  ok "Afrog、RAD 与 Worker 扩展安装完成"
  rm -rf "$tmp_dir"
}
