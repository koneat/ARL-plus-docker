# shellcheck shell=bash

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "请使用 root 运行：sudo bash $0"

  [[ -r /etc/os-release ]] || die "无法识别操作系统"
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "第一阶段脚本当前只支持 Ubuntu，检测到：${PRETTY_NAME:-unknown}"
  fi
}

validate_env() {
  local bool_name bool_value port_name port_value image_name image_value

  for port_name in MCP_LOCAL_PORT MCP_EXTERNAL_PORT ARL_HTTPS_PORT XRAY_SOCKS_PORT CHAITIN_XRAY_PORT; do
    port_value="${!port_name}"
    [[ "$port_value" =~ ^[0-9]+$ ]] || die "${port_name} 必须是整数"
    (( port_value >= 1 && port_value <= 65535 )) || die "${port_name} 超出范围"
  done

  [[ "$MCP_LOCAL_PORT" != "$MCP_EXTERNAL_PORT" ]] ||
    die "MCP_LOCAL_PORT 与 MCP_EXTERNAL_PORT 不能相同"

  case "$MCP_READ_ONLY" in true|false) ;; *) die "MCP_READ_ONLY 只能是 true 或 false" ;; esac
  case "$MCP_ALLOW_LOCAL_UNAUTHENTICATED" in true|false) ;; *) die "MCP_ALLOW_LOCAL_UNAUTHENTICATED 只能是 true 或 false" ;; esac
  case "$DISABLE_UFW" in true|false) ;; *) die "DISABLE_UFW 只能是 true 或 false" ;; esac

  for bool_name in ENABLE_VLESS_PROXY ENABLE_ARL_HTTP_PROXY FORCE_ARL_PROXY ENABLE_CHAITIN_XRAY ENABLE_SMART_WILDCARD ENABLE_SCANNER_STACK BUILD_SCANNER_IMAGE ENABLE_WORKER_EXTENSIONS INSTALL_CHROMIUM REPORT_WORLD_READABLE; do
    bool_value="${!bool_name}"
    case "$bool_value" in true|false) ;; *) die "${bool_name} 只能是 true 或 false" ;; esac
  done

  for image_name in ARL_BASE_IMAGE ARL_ENHANCED_WORKER_IMAGE ARL_PROXY_RUNTIME_IMAGE; do
    image_value="${!image_name}"
    [[ -n "$image_value" && "$image_value" != *[[:space:]]* ]] ||
      die "${image_name} 不能为空或包含空白字符"
  done

  if [[ -n "$ARL_MONGO_URI" && "$ARL_MONGO_URI" != mongodb://* && "$ARL_MONGO_URI" != mongodb+srv://* ]]; then
    die "ARL_MONGO_URI 必须以 mongodb:// 或 mongodb+srv:// 开头"
  fi

  if [[ "$ENABLE_ARL_HTTP_PROXY" == "true" && "$ENABLE_VLESS_PROXY" != "true" ]]; then
    die "ENABLE_ARL_HTTP_PROXY=true 时必须同时启用 ENABLE_VLESS_PROXY"
  fi

  if [[ "$ENABLE_ARL_HTTP_PROXY" == "true" && "$ENABLE_SMART_WILDCARD" != "true" && "$ENABLE_WORKER_EXTENSIONS" != "true" ]]; then
    die "启用 ARL HTTP 代理时必须启用智能 Worker 或持久化增强 Worker，以保证 Worker 内置 PySocks"
  fi

  if [[ "$MCP_LOCAL_BIND_IP" != "127.0.0.1" && "$MCP_LOCAL_BIND_IP" != "::1" ]]; then
    die "MCP_LOCAL_BIND_IP 必须是 127.0.0.1 或 ::1，禁止把免认证入口绑定到外网"
  fi

  if [[ "$MCP_ALLOW_LOCAL_UNAUTHENTICATED" == "true" ]]; then
    ok "MCP 本机入口免认证，仅监听 ${MCP_LOCAL_BIND_IP}:${MCP_LOCAL_PORT}"
  fi
  if [[ "$MCP_EXTERNAL_BIND_IP" == "0.0.0.0" || "$MCP_EXTERNAL_BIND_IP" == "::" ]]; then
    warn "MCP 外部入口将监听所有网卡：${MCP_EXTERNAL_BIND_IP}:${MCP_EXTERNAL_PORT}；该入口仍强制 Token"
  else
    ok "MCP 外部入口绑定 ${MCP_EXTERNAL_BIND_IP}:${MCP_EXTERNAL_PORT}，适合由本机反向代理或隧道转发"
  fi
}

apt_common_options=(
  -o DPkg::Lock::Timeout=300
  -o Binary::apt-get::DPkg::Lock::Timeout=300
  -o Acquire::Retries=5
  -o Acquire::Languages=none
)

apt_update_resilient() {
  local attempt max_attempts=6 delay_seconds

  for attempt in $(seq 1 "$max_attempts"); do
    if apt-get "${apt_common_options[@]}" update; then
      return 0
    fi

    if (( attempt == max_attempts )); then
      break
    fi

    delay_seconds=$((attempt * 5))
    warn "APT 索引更新失败（第 ${attempt}/${max_attempts} 次），可能是镜像同步中；清理损坏索引后 ${delay_seconds} 秒重试"

    rm -rf /var/lib/apt/lists/partial/*
    find /var/lib/apt/lists -maxdepth 1 -type f \
      \( -name '*Translation*' -o -name '*i18n*' \) -delete 2>/dev/null || true
    apt-get clean || true
    sleep "$delay_seconds"
  done

  die "APT 索引连续 ${max_attempts} 次更新失败；请检查 Ubuntu 镜像状态或更换镜像"
}

apt_run() {
  if [[ "${1:-}" == "update" ]]; then
    shift
    apt_update_resilient "$@"
    return
  fi

  apt-get "${apt_common_options[@]}" "$@"
}

install_base_packages() {
  export DEBIAN_FRONTEND=noninteractive

  log "安装基础软件；APT 锁最多等待 300 秒"
  apt_run update
  apt_run install -y \
    ca-certificates curl git jq wget unzip tmux \
    coreutils python3 python3-yaml gnupg lsb-release psmisc \
    iproute2 netcat-openbsd libpcap0.8 procps acl

  ok "基础软件已安装"
}

install_docker_if_needed() {
  if command -v docker >/dev/null 2>&1; then
    systemctl enable --now docker

    if docker compose version >/dev/null 2>&1; then
      ok "检测到 Docker Engine 与 Compose Plugin"
      return
    fi

    log "检测到现有 Docker，仅补装 Compose v2，不卸载现有 Docker"
    apt_run install -y docker-compose-v2 2>/dev/null || \
      apt_run install -y docker-compose-plugin 2>/dev/null || true

    if ! docker compose version >/dev/null 2>&1; then
      local machine_arch compose_arch plugin_dir plugin_path compose_url
      machine_arch="$(uname -m)"
      case "$machine_arch" in
        x86_64|amd64) compose_arch="x86_64" ;;
        aarch64|arm64) compose_arch="aarch64" ;;
        armv7l|armv7) compose_arch="armv7" ;;
        *) die "不支持自动安装 Compose v2 的架构：$machine_arch" ;;
      esac

      plugin_dir="/usr/local/lib/docker/cli-plugins"
      plugin_path="${plugin_dir}/docker-compose"
      compose_url="https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${compose_arch}"
      mkdir -p "$plugin_dir"
      curl -fL --retry 5 --retry-all-errors --connect-timeout 20 --max-time 600 \
        "$compose_url" -o "${plugin_path}.tmp"
      install -m 0755 "${plugin_path}.tmp" "$plugin_path"
      rm -f "${plugin_path}.tmp"
    fi

    docker compose version >/dev/null 2>&1 || die "Compose v2 安装失败"
    ok "Compose v2 补装完成"
    return
  fi

  log "未检测到 Docker，安装 Docker 官方 Engine 与 Compose Plugin"

  apt_run remove -y \
    docker.io docker-compose docker-compose-v2 docker-doc podman-docker \
    containerd runc 2>/dev/null || true

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  local codename arch
  codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
  arch="$(dpkg --print-architecture)"

  cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${codename}
Components: stable
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/docker.asc
EOF

  apt_run update
  apt_run install -y \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

  systemctl enable --now docker
  docker version >/dev/null
  docker compose version >/dev/null
  ok "Docker 安装完成"
}

configure_firewall() {
  if [[ "$DISABLE_UFW" != "true" ]]; then
    ok "未修改 UFW"
    return
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw --force disable || true
    warn "已按配置关闭 UFW"
  else
    warn "系统没有安装 UFW，跳过"
  fi
}

check_dns() {
  if getent ahosts github.com >/dev/null 2>&1; then
    ok "DNS 解析正常"
  else
    die "DNS 无法解析 github.com。未自动覆盖 /etc/resolv.conf，请先修复 systemd-resolved 或网络配置"
  fi
}
