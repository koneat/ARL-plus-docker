# shellcheck shell=bash

prepare_config() {
  local config="${ARL_DIR}/config-docker.yaml"
  [[ -f "$config" ]] || die "仓库缺少 config-docker.yaml"

  backup_file "$config"

  if [[ -n "$CONFIG_SOURCE_URL" ]]; then
    log "下载指定 ARL 配置模板"
    curl -fL --retry 3 --connect-timeout 15 \
      "$CONFIG_SOURCE_URL" -o "${config}.new"
    mv "${config}.new" "$config"
  fi

  export TARGET_CONFIG="$config"
  python3 <<'PY'
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

path = Path(os.environ["TARGET_CONFIG"])
text = path.read_text(encoding="utf-8")
lines = text.splitlines(keepends=True)

def yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return json.dumps(str(value), ensure_ascii=False)

def set_nested(keys: list[str], value: Any) -> None:
    global lines
    indent = 0
    start = 0

    for depth, key in enumerate(keys[:-1]):
        pattern = re.compile(rf"^{' ' * indent}{re.escape(key)}\s*:\s*(?:#.*)?$")
        found = None
        for idx in range(start, len(lines)):
            raw = lines[idx].rstrip("\r\n")
            current_indent = len(raw) - len(raw.lstrip(" "))
            if idx > start and current_indent < indent:
                break
            if pattern.match(raw):
                found = idx
                break

        if found is None:
            insert_at = len(lines)
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.insert(insert_at, f"{' ' * indent}{key}:\n")
            found = insert_at

        start = found + 1
        indent += 2

    leaf = keys[-1]
    leaf_pattern = re.compile(rf"^({' ' * indent}{re.escape(leaf)}\s*:\s*).*$")
    section_end = len(lines)

    for idx in range(start, len(lines)):
        raw = lines[idx].rstrip("\r\n")
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        current_indent = len(raw) - len(raw.lstrip(" "))
        if current_indent < indent:
            section_end = idx
            break
        match = leaf_pattern.match(raw)
        if match:
            newline = "\n" if lines[idx].endswith("\n") else ""
            lines[idx] = f"{match.group(1)}{yaml_scalar(value)}{newline}"
            return

    lines.insert(section_end, f"{' ' * indent}{leaf}: {yaml_scalar(value)}\n")

updates: list[tuple[list[str], Any]] = []

def add(env_name: str, path_keys: list[str]) -> None:
    value = os.environ.get(env_name, "")
    if value != "":
        updates.append((path_keys, value))

add("ARL_MONGO_URI", ["MONGO", "URI"])
add("ARL_MONGO_DB", ["MONGO", "DB"])
add("FOFA_EMAIL", ["FOFA", "EMAIL"])
add("FOFA_KEY", ["FOFA", "KEY"])
add("HUNTER_API_KEY", ["QUERY_PLUGIN", "hunter_qax", "api_key"])
add("QUAKE_TOKEN", ["QUERY_PLUGIN", "quake_360", "quake_token"])
add("ZOOMEYE_API_KEY", ["QUERY_PLUGIN", "zoomeye", "api_key"])
add("GITHUB_TOKEN", ["GITHUB", "TOKEN"])
add("HTTP_PROXY_URL", ["PROXY", "HTTP_URL"])
add("ARL_API_KEY", ["ARL", "API_KEY"])

for key_path, value in updates:
    set_nested(key_path, value)

path.write_text("".join(lines), encoding="utf-8")
PY

  python3 - <<PY
import yaml
with open("$config", "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)
assert isinstance(data, dict)
assert "MONGO" in data and "ARL" in data
print("[OK] config-docker.yaml YAML 校验通过")
PY

  chmod 600 "$config"

  # MCP 镜像以 UID 10001 运行。仅授予该 UID 读取权限，
  # 不把包含 MongoDB/FOFA 等密钥的配置改成全局可读。
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -m u:10001:r-- "$config"
    ok "已授予 MCP UID 10001 读取 config-docker.yaml 的 ACL 权限"
  else
    warn "系统缺少 setfacl，临时使用 chmod 604 兼容 MCP 读取"
    chmod 604 "$config"
  fi
}
