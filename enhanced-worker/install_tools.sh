#!/usr/bin/env bash
set -Eeuo pipefail

AFROG_VERSION="${AFROG_VERSION:-v3.5.3}"
RAD_VERSION="${RAD_VERSION:-1.0}"
INSTALL_CHROMIUM="${INSTALL_CHROMIUM:-true}"
ARL_MERGE_FULL_DOMAIN_WORDLIST="${ARL_MERGE_FULL_DOMAIN_WORDLIST:-false}"

log() {
  printf '[enhanced-worker] %s\n' "$*"
}

install_packages() {
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install epel-release || true
    dnf -y install \
      ca-certificates curl unzip tar gzip findutils procps-ng \
      libpcap libpcap-devel nss atk at-spi2-atk cups-libs libdrm \
      libXcomposite libXdamage libXrandr mesa-libgbm pango alsa-lib
    if [[ "$INSTALL_CHROMIUM" == 'true' ]]; then
      dnf -y install chromium || true
    fi
    dnf clean all
    return
  fi

  if command -v yum >/dev/null 2>&1; then
    yum -y install epel-release || true
    yum -y install \
      ca-certificates curl unzip tar gzip findutils procps-ng \
      libpcap libpcap-devel nss atk at-spi2-atk cups-libs libdrm \
      libXcomposite libXdamage libXrandr mesa-libgbm pango alsa-lib
    if [[ "$INSTALL_CHROMIUM" == 'true' ]]; then
      yum -y install chromium || true
    fi
    yum clean all
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates curl unzip tar gzip findutils procps libpcap0.8 libpcap-dev
    if [[ "$INSTALL_CHROMIUM" == 'true' ]]; then
      apt-get install -y --no-install-recommends chromium || \
        apt-get install -y --no-install-recommends chromium-browser
    fi
    rm -rf /var/lib/apt/lists/*
    return
  fi

  echo '[ERROR] unsupported package manager' >&2
  exit 1
}

arch_name() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    *)
      echo "[ERROR] unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

install_afrog() {
  local arch archive url tmp binary
  arch="$(arch_name)"
  archive="afrog_${AFROG_VERSION#v}_linux_${arch}.zip"
  url="https://github.com/zan8in/afrog/releases/download/${AFROG_VERSION}/${archive}"
  tmp="$(mktemp -d)"
  curl -fsSL --retry 5 --retry-delay 2 "$url" -o "$tmp/$archive"
  unzip -oq "$tmp/$archive" -d "$tmp/unpacked"
  binary="$(find "$tmp/unpacked" -type f -name afrog | head -n1)"
  [[ -n "$binary" ]] || {
    echo '[ERROR] afrog binary missing from release archive' >&2
    exit 1
  }
  install -m 0755 "$binary" /usr/local/bin/afrog
  rm -rf "$tmp"
}

install_rad() {
  local arch archive url tmp binary
  arch="$(arch_name)"
  archive="rad_linux_${arch}.zip"
  url="https://github.com/chaitin/rad/releases/download/${RAD_VERSION}/${archive}"
  tmp="$(mktemp -d)"
  curl -fsSL --retry 5 --retry-delay 2 "$url" -o "$tmp/$archive"
  unzip -oq "$tmp/$archive" -d "$tmp/unpacked"
  binary="$(find "$tmp/unpacked" -type f -name rad | head -n1)"
  [[ -n "$binary" ]] || {
    echo '[ERROR] rad binary missing from release archive' >&2
    exit 1
  }
  install -m 0755 "$binary" /usr/local/bin/rad
  rm -rf "$tmp"
}

ensure_libpcap_compat() {
  local candidate=''
  if [[ -e /usr/lib64/libpcap.so.0.8 ]]; then
    return
  fi

  candidate="$(find /usr/lib64 /usr/lib /lib64 /lib /usr/lib/x86_64-linux-gnu \
    -maxdepth 2 -type f -o -type l 2>/dev/null | grep -E '/libpcap\.so(\.[0-9.]+)?$' | head -n1 || true)"
  if [[ -z "$candidate" ]]; then
    echo '[ERROR] libpcap shared library not found' >&2
    exit 1
  fi

  mkdir -p /usr/lib64
  ln -sfn "$candidate" /usr/lib64/libpcap.so.0.8
}

install_python_dependencies() {
  python3.6 -m pip install --no-cache-dir 'PySocks>=1.7.1,<2'
}

install_vendored_wordlists() {
  local target='/opt/arl-wordlists'

  VENDORED_FILE_DICT='/tmp/combined-file-dict.txt'
  VENDORED_DOMAIN_DICT='/tmp/combined-domain-dict.txt'

  for path in \
    /tmp/vendor-api-endpoints.txt \
    /tmp/vendor-raft-small-files.txt \
    /tmp/vendor-subdomains-main.txt \
    /tmp/vendor-SOURCES.env \
    /tmp/vendor-LICENSE.SecLists; do
    [[ -s "$path" ]] || {
      echo "[ERROR] vendored wordlist missing from image build context: $path" >&2
      exit 1
    }
  done

  mkdir -p "$target"
  install -m 0644 /tmp/vendor-api-endpoints.txt "$target/api-endpoints.txt"
  install -m 0644 /tmp/vendor-raft-small-files.txt "$target/raft-small-files.txt"
  install -m 0644 /tmp/vendor-subdomains-main.txt "$target/subdomains-main.txt"
  install -m 0644 /tmp/vendor-SOURCES.env "$target/SOURCES.env"
  install -m 0644 /tmp/vendor-LICENSE.SecLists "$target/LICENSE.SecLists"

  cat \
    /tmp/high-value-paths.txt \
    /tmp/vendor-api-endpoints.txt \
    /tmp/vendor-raft-small-files.txt \
    >"$VENDORED_FILE_DICT"

  if [[ "$ARL_MERGE_FULL_DOMAIN_WORDLIST" == 'true' ]]; then
    cat /tmp/high-value-subdomains.txt /tmp/vendor-subdomains-main.txt >"$VENDORED_DOMAIN_DICT"
    log '已启用完整 16 万级子域名字典合并'
  else
    cp /tmp/high-value-subdomains.txt "$VENDORED_DOMAIN_DICT"
    log '完整子域名字典已内置到 /opt/arl-wordlists，默认不自动合并到每次扫描'
  fi
}

log '安装系统依赖、Chromium、libpcap 与 PySocks'
install_packages
ensure_libpcap_compat
install_python_dependencies
log "安装 Afrog ${AFROG_VERSION}"
install_afrog
log "安装 RAD ${RAD_VERSION}"
install_rad

log '应用智能泛解析补丁'
python3.6 /tmp/patch_arl.py

log '安装仓库内置字典并合并 API/文件路径'
install_vendored_wordlists

log '合并高价值路径/子域名字典并安装 Nuclei、Afrog/xray 任务适配器'
python3.6 /tmp/patch_worker.py \
  --file-dict "$VENDORED_FILE_DICT" \
  --domain-dict "$VENDORED_DOMAIN_DICT" \
  --nuclei-adapter /tmp/nuclei_scan.py \
  --afrog-adapter /tmp/afrog_scan.py

install -m 0755 /tmp/afrog-arl /usr/local/bin/afrog-arl
install -m 0755 /tmp/arl-report-index /usr/local/bin/arl-report-index

python3.6 -m py_compile \
  /code/app/services/massdns.py \
  /code/app/services/wildcardSmart.py \
  /code/app/services/nuclei_scan.py \
  /code/app/services/afrog_scan.py \
  /code/app/services/commonTask.py \
  /code/app/tasks/domain.py
python3.6 -c 'import socks; from app.services.wildcardSmart import WildcardSmartFilter; from app.services.nuclei_scan import NucleiScan; from app.services.afrog_scan import AfrogTaskScan; from app.services.commonTask import WebSiteFetch; print("enhanced-worker-import-ok")'
command -v nuclei >/dev/null
command -v afrog >/dev/null
command -v rad >/dev/null
test -e /usr/lib64/libpcap.so.0.8
test -s /opt/arl-wordlists/api-endpoints.txt
test -s /opt/arl-wordlists/raft-small-files.txt
test -s /opt/arl-wordlists/subdomains-main.txt
grep -qx 'api/auth/login' /opt/arl-wordlists/api-endpoints.txt
grep -qx 'index.php' /opt/arl-wordlists/raft-small-files.txt
grep -qx 'admin' /opt/arl-wordlists/subdomains-main.txt
grep -qx 'api/auth/login' /code/app/dicts/file_top_2000.txt
grep -qx 'index.php' /code/app/dicts/file_top_2000.txt
grep -q 'def afrog_scan(self):' /code/app/services/commonTask.py
grep -q 'self.run_func("afrog_scan", self.afrog_scan)' /code/app/services/commonTask.py
if [[ "$INSTALL_CHROMIUM" == 'true' ]]; then
  command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1
fi

rm -f \
  /tmp/patch_arl.py \
  /tmp/patch_worker.py \
  /tmp/nuclei_scan.py \
  /tmp/afrog_scan.py \
  /tmp/high-value-paths.txt \
  /tmp/high-value-subdomains.txt \
  /tmp/vendor-api-endpoints.txt \
  /tmp/vendor-raft-small-files.txt \
  /tmp/vendor-subdomains-main.txt \
  /tmp/vendor-SOURCES.env \
  /tmp/vendor-LICENSE.SecLists \
  /tmp/combined-file-dict.txt \
  /tmp/combined-domain-dict.txt \
  /tmp/afrog-arl \
  /tmp/arl-report-index

log '持久化 Worker 扩展安装完成；Afrog/xray 任务钩子已通过镜像内导入检查'
