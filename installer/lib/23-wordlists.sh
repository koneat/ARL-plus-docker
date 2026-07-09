# shellcheck shell=bash

wordlist_env_set() {
  local file="$1"
  local key="$2"
  local value="$3"

  [[ -n "$file" && -f "$file" ]] || return 0
  python3 - "$file" "$key" "$value" <<'PY'
from __future__ import annotations
import os
import re
import shlex
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
pattern = re.compile(rf"^[ \t]*(?:export[ \t]+)?{re.escape(key)}=")
replacement = f"{key}={shlex.quote(value)}\n"
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
output = []
found = False
for line in lines:
    if pattern.match(line):
        if not found:
            output.append(replacement)
            found = True
        continue
    output.append(line)
if not found:
    if output and not output[-1].endswith(("\n", "\r")):
        output[-1] += "\n"
    output.append(replacement)
mode = path.stat().st_mode & 0o777
fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.writelines(output)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
}

prepare_vendored_wordlists() {
  local vendor_root="${ARL_DIR}/wordlists/vendor"
  local api_path="${vendor_root}/api-endpoints.txt"
  local fuzz_path="${vendor_root}/raft-small-files.txt"
  local domain_path="${vendor_root}/subdomains-main.txt"
  local sources_path="${vendor_root}/SOURCES.env"
  local api_lines fuzz_lines domain_lines

  for path in "$api_path" "$fuzz_path" "$domain_path" "$sources_path"; do
    [[ -s "$path" ]] || die "仓库内置字典缺失或为空：$path"
  done

  api_lines="$(grep -cve '^[[:space:]]*$' "$api_path")"
  fuzz_lines="$(grep -cve '^[[:space:]]*$' "$fuzz_path")"
  domain_lines="$(grep -cve '^[[:space:]]*$' "$domain_path")"

  [[ "$api_lines" -ge 250 ]] || die "API 字典行数异常：$api_lines"
  [[ "$fuzz_lines" -ge 10000 ]] || die "Fuzz 字典行数异常：$fuzz_lines"
  [[ "$domain_lines" -ge 100000 ]] || die "子域名字典行数异常：$domain_lines"

  API_DICT_URL="file://${api_path}"
  FUZZ_DICT_URL="file://${fuzz_path}"
  DOMAIN_DICT_URL="file://${domain_path}"
  export API_DICT_URL FUZZ_DICT_URL DOMAIN_DICT_URL

  # 把旧私密安装脚本留下的第三方 Raw 地址原子替换为本仓库本地路径。
  wordlist_env_set "$ENV_FILE" API_DICT_URL "$API_DICT_URL"
  wordlist_env_set "$ENV_FILE" FUZZ_DICT_URL "$FUZZ_DICT_URL"
  wordlist_env_set "$ENV_FILE" DOMAIN_DICT_URL "$DOMAIN_DICT_URL"

  ok "仓库内置字典验证通过：API=${api_lines}，Fuzz=${fuzz_lines}，Domain=${domain_lines}"
  ok "字典来源已切换为本机仓库，不再依赖第三方 raw.githubusercontent.com"
}
