#!/usr/bin/env bash
set -Eeuo pipefail

AFROG_VERSION="${AFROG_VERSION:-v3.5.3}"
RAD_VERSION="${RAD_VERSION:-1.0}"
INSTALL_CHROMIUM="${INSTALL_CHROMIUM:-true}"
ARL_MERGE_FULL_DOMAIN_WORDLIST="${ARL_MERGE_FULL_DOMAIN_WORDLIST:-false}"
WORK_DIR="$(mktemp -d)"
VENDORED_FILE_DICT=''
VENDORED_DOMAIN_DICT=''
trap 'rm -rf "$WORK_DIR"' EXIT

log() {
  printf '[enhanced-worker] %s\n' "$*"
}

fetch() {
  local url="$1"
  local output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 5 --retry-delay 2 --connect-timeout 20 --max-time 1200 \
      -A 'arl-enhanced-worker-builder/2026.07' \
      "$url" -o "$output"
  elif command -v wget >/dev/null 2>&1; then
    wget --tries=5 --timeout=20 -O "$output" "$url"
  else
    python3.6 - "$url" "$output" <<'PY'
from __future__ import print_function
import sys
try:
    from urllib.request import urlretrieve
except ImportError:
    from urllib import urlretrieve
urlretrieve(sys.argv[1], sys.argv[2])
PY
  fi
}

prepare_yum_repositories() {
  if yum -q makecache >/dev/null 2>&1; then
    return 0
  fi
  log '默认 CentOS 7 仓库不可用，切换到归档镜像配置'
  fetch https://mirrors.aliyun.com/repo/Centos-7.repo /etc/yum.repos.d/CentOS-Base.repo
  fetch https://mirrors.aliyun.com/repo/epel-7.repo /etc/yum.repos.d/epel.repo
  yum clean all
  yum -q makecache
}

install_packages() {
  if command -v yum >/dev/null 2>&1; then
    prepare_yum_repositories
    yum install -y ca-certificates curl unzip libpcap
    if [[ "$INSTALL_CHROMIUM" == 'true' ]]; then
      if ! yum install -y chromium; then
        fetch https://mirrors.aliyun.com/repo/epel-7.repo /etc/yum.repos.d/epel.repo
        yum clean all
        yum -q makecache
        yum install -y chromium
      fi
    fi
    yum clean all
    rm -rf /var/cache/yum
  elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    packages=(ca-certificates curl unzip libpcap0.8)
    [[ "$INSTALL_CHROMIUM" == 'true' ]] && packages+=(chromium)
    apt-get install -y --no-install-recommends "${packages[@]}"
    rm -rf /var/lib/apt/lists/*
  else
    echo '[ERROR] unsupported base image package manager' >&2
    exit 1
  fi

  python3.6 -m pip install --disable-pip-version-check --no-cache-dir 'PySocks==1.7.1'

  local libpcap_path
  libpcap_path="$(ldconfig -p 2>/dev/null | sed -n '/libpcap\.so/{s/.*=>[[:space:]]*//;p;q;}')"
  [[ -n "$libpcap_path" && -f "$libpcap_path" ]] || {
    echo '[ERROR] libpcap shared library was not found after package installation' >&2
    exit 1
  }
  mkdir -p /usr/lib64
  ln -sfn "$libpcap_path" /usr/lib64/libpcap.so.0.8
}

download_release_asset() {
  local repository="$1"
  local tag="$2"
  local pattern="$3"
  local output="$4"
  local metadata="${WORK_DIR}/release.json"
  local url

  fetch "https://api.github.com/repos/${repository}/releases/tags/${tag}" "$metadata"
  url="$(python3.6 - "$metadata" "$pattern" <<'PY'
from __future__ import print_function
import io
import json
import re
import sys
with io.open(sys.argv[1], 'r', encoding='utf-8') as handle:
    data = json.load(handle)
pattern = re.compile(sys.argv[2])
for asset in data.get('assets', []):
    if pattern.search(asset.get('name', '')):
        print(asset.get('browser_download_url', ''))
        break
PY
)"
  [[ -n "$url" ]] || {
    echo "[ERROR] release asset not found: ${repository} ${tag} ${pattern}" >&2
    exit 1
  }
  fetch "$url" "$output"
}

install_afrog() {
  local archive="${WORK_DIR}/afrog.zip"
  local unpack="${WORK_DIR}/afrog"
  local binary
  download_release_asset zan8in/afrog "$AFROG_VERSION" 'linux_amd64\.zip$' "$archive"
  mkdir -p "$unpack"
  unzip -oq "$archive" -d "$unpack"
  binary="$(find "$unpack" -type f -name afrog -perm /111 | head -n 1)"
  [[ -n "$binary" ]] || {
    echo '[ERROR] afrog executable missing from release archive' >&2
    exit 1
  }
  install -m 0755 "$binary" /usr/local/bin/afrog
}

install_rad() {
  local archive="${WORK_DIR}/rad.zip"
  local unpack="${WORK_DIR}/rad"
  local binary
  download_release_asset chaitin/rad "$RAD_VERSION" 'rad_linux_amd64\.zip$' "$archive"
  mkdir -p "$unpack"
  unzip -oq "$archive" -d "$unpack"
  binary="$(find "$unpack" -type f \( -name rad_linux_amd64 -o -name rad \) | head -n 1)"
  [[ -n "$binary" ]] || {
    echo '[ERROR] rad executable missing from release archive' >&2
    exit 1
  }
  install -m 0755 "$binary" /usr/local/bin/rad
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
