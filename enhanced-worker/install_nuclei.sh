#!/usr/bin/env bash
set -Eeuo pipefail

NUCLEI_VERSION="${NUCLEI_VERSION:-v3.11.0}"
TEMPLATE_DIR="${ARL_NUCLEI_TEMPLATE_DIR:-/root/nuclei-templates}"
TEMPLATE_MINIMUM="${ARL_NUCLEI_TEMPLATE_MIN_COUNT:-50}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

version_number="${NUCLEI_VERSION#v}"
archive="$WORK_DIR/nuclei.zip"
download_url="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${version_number}_linux_amd64.zip"

printf '[enhanced-worker] 安装 Nuclei %s\n' "$NUCLEI_VERSION"
curl -fL --retry 5 --retry-delay 2 --connect-timeout 20 --max-time 1200 \
  -A 'arl-enhanced-worker-builder/2026.07' \
  "$download_url" -o "$archive"
unzip -oq "$archive" -d "$WORK_DIR/unpacked"
binary="$(find "$WORK_DIR/unpacked" -type f -name nuclei -perm /111 | head -n 1)"
[[ -n "$binary" ]] || {
  echo '[enhanced-worker][ERROR] nuclei executable missing from release archive' >&2
  exit 1
}
install -m 0755 "$binary" /usr/local/bin/nuclei
nuclei -version

mkdir -p "$TEMPLATE_DIR"
printf '[enhanced-worker] 更新 Nuclei 模板到 %s\n' "$TEMPLATE_DIR"
HOME=/root nuclei -ut -ud "$TEMPLATE_DIR"

template_count="$(
  find "$TEMPLATE_DIR" -type f \( -name '*.yaml' -o -name '*.yml' \) |
    wc -l | tr -d ' '
)"
if (( template_count < TEMPLATE_MINIMUM )); then
  echo "[enhanced-worker][ERROR] Nuclei 模板不足：${template_count} < ${TEMPLATE_MINIMUM}" >&2
  exit 1
fi

selected_count="$(
  HOME=/root nuclei -tl -silent -t "$TEMPLATE_DIR" \
    -exclude-tags dos,fuzz,intrusive,bruteforce |
    grep -cve '^[[:space:]]*$' || true
)"
if (( selected_count == 0 )); then
  echo "[enhanced-worker][ERROR] 模板文件存在但 Nuclei 无法加载：${TEMPLATE_DIR}" >&2
  exit 1
fi

printf '[enhanced-worker] Nuclei 就绪：模板文件 %s，可加载 %s\n' \
  "$template_count" "$selected_count"
