configure_afrog_callback() {
  local config="$1"
  [[ -f "$config" ]] || return 0

  python3 - "$config" "$AFROG_CALLBACK_DOMAIN" "$AFROG_CALLBACK_API_URL" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
domain = sys.argv[2]
api_url = sys.argv[3]
text = path.read_text(encoding="utf-8")

if re.search(r"(?m)^\s*domain:\s*.*$", text):
    text = re.sub(r'(?m)^(\s*domain:\s*).*$',
                  lambda m: m.group(1) + f'"{domain}"', text, count=1)
if re.search(r"(?m)^\s*api_url:\s*.*$", text):
    text = re.sub(r'(?m)^(\s*api_url:\s*).*$',
                  lambda m: m.group(1) + f'"{api_url}"', text, count=1)

path.write_text(text, encoding="utf-8")
PY
}

patch_worker_packages() {
  log "检查 Worker 中的 Chromium、libpcap 与 PySocks"

  if ! docker exec arl_worker sh -lc '
    set -e
    python3.6 -m pip install --disable-pip-version-check PySocks
    if command -v yum >/dev/null 2>&1; then
      if ! yum -q makecache >/dev/null 2>&1; then
        curl -fsSL https://mirrors.aliyun.com/repo/Centos-7.repo \
          -o /etc/yum.repos.d/CentOS-Base.repo || true
      fi
      yum install -y chromium libpcap
    fi
    libpcap_path="$(ldconfig -p 2>/dev/null | sed -n "/libpcap\\.so/{s/.*=>[[:space:]]*//;p;q;}")"
    if [ -n "$libpcap_path" ]; then
      ln -sf "$libpcap_path" /usr/lib64/libpcap.so.0.8
    fi
  '; then
    warn "Worker 的 Chromium/libpcap 安装失败；ARL 主服务和 MCP 不受影响"
  fi
}

optional_download() {
  local url="$1"
  local output="$2"

  if [[ -z "$url" ]]; then
    return 1
  fi

  if curl -fL --retry 3 --retry-all-errors --connect-timeout 15 --max-time 600 \
      "$url" -o "${output}.tmp"; then
    mv "${output}.tmp" "$output"
    return 0
  fi
  rm -f "${output}.tmp"
  warn "可选文件下载失败，已跳过：$url"
  return 1
}

patch_worker_dicts() {
  local tmp_dir="$1"
  local api_file="${tmp_dir}/api.txt"
  local fuzz_file="${tmp_dir}/fuzz.txt"
  local domain_file="${tmp_dir}/domain.txt"
  local wih_file="${tmp_dir}/wih_rules.yml"
  local fileleak_file="${tmp_dir}/fileLeak.py"
  local nuclei_scan_file="${tmp_dir}/nuclei_scan.py"

  optional_download "$API_DICT_URL" "$api_file" || true
  optional_download "$FUZZ_DICT_URL" "$fuzz_file" || true
  optional_download "$DOMAIN_DICT_URL" "$domain_file" || true
  optional_download "$WIH_RULES_URL" "$wih_file" || true
  optional_download "$FILELEAK_SERVICE_URL" "$fileleak_file" || true
  optional_download "$NUCLEI_SCAN_SERVICE_URL" "$nuclei_scan_file" || true

  if [[ -s "$api_file" || -s "$fuzz_file" ]]; then
    {
      [[ -s "$api_file" ]] && tr '[:space:]' '\n' < "$api_file"
      [[ -s "$fuzz_file" ]] && tr '[:space:]' '\n' < "$fuzz_file"
    } | sed '/^[[:space:]]*$/d' | docker exec -i arl_worker sh -lc '
      set -e
      target=/code/app/dicts/file_top_2000.txt
      tmp="$(mktemp)"
      cat "$target" - | sed "/^[[:space:]]*$/d" | sort -u > "$tmp"
      cat "$tmp" > "$target"
      rm -f "$tmp"
    '
    ok "文件泄漏字典合并完成"
  fi

  if [[ -s "$domain_file" ]]; then
    cat "$domain_file" | docker exec -i arl_worker sh -lc '
      set -e
      target=/code/app/dicts/domain_2w.txt
      tmp="$(mktemp)"
      cat "$target" - | sed "/^[[:space:]]*$/d" | sort -u > "$tmp"
      cat "$tmp" > "$target"
      rm -f "$tmp"
    '
    ok "子域名字典合并完成"
  fi

  [[ -s "$wih_file" ]] &&
    docker cp "$wih_file" arl_worker:/code/app/dicts/wih_rules.yml
  [[ -s "$fileleak_file" ]] &&
    docker cp "$fileleak_file" arl_worker:/code/app/services/fileLeak.py
  [[ -s "$nuclei_scan_file" ]] &&
    docker cp "$nuclei_scan_file" arl_worker:/code/app/services/nuclei_scan.py

  docker exec arl_worker sh -lc '
    set -e
    for file in $(find /opt/ARL-NPoC/xing/dicts -type f -name "password_*.txt" 2>/dev/null); do
      for value in "%user%@2024" "%user%@2025" "Abc@1234" "000000"; do
        grep -qxF "$value" "$file" || printf "%s\n" "$value" >> "$file"
      done
    done

    info=/code/app/services/infoHunter.py
    if [ -f "$info" ] && grep -q "\"-J\"," "$info" && ! grep -q "\"--dc\"" "$info"; then
      sed -i "s#\"-J\",#\"-J\",\\n                   \"-f\",\\n                   \"--dc\",#g" "$info"
    fi

    if command -v nuclei >/dev/null 2>&1; then
      nuclei -update-templates >/dev/null 2>&1 ||
        nuclei -update >/dev/null 2>&1 || true
    fi
  '
}
