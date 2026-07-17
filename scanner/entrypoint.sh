#!/usr/bin/env bash
set -Eeuo pipefail

RESULT_ROOT="${SCANNER_V2_RESULT_ROOT:-/work/results}"
STATE_ROOT="${SCANNER_V2_STATE_ROOT:-/root/.config/scanner-api}"
TEMPLATE_ROOT="${NUCLEI_TEMPLATE_DIR:-/root/nuclei-templates}"

mkdir -p \
  "$RESULT_ROOT" \
  "$STATE_ROOT" \
  "$TEMPLATE_ROOT" \
  /opt/pocs/nuclei \
  /opt/pocs/afrog

check_writable_dir() {
  local name="$1"
  local directory="$2"
  local probe="${directory}/.arl-write-probe.$$"

  if ! (umask 077; : >"$probe" && rm -f "$probe"); then
    echo "[scanner][FATAL] ${name} 不可写：${directory}" >&2
    echo "[scanner][FATAL] Scanner V2 在 cap_drop=ALL 下不会绕过宿主机目录权限。" >&2
    echo "[scanner][FATAL] 请确保对应宿主机目录归 UID 0/GID 0 所有并至少为 0755。" >&2
    ls -ld "$directory" >&2 || true
    stat -c '[scanner][FATAL] mode=%a uid=%u gid=%g path=%n' "$directory" >&2 || true
    exit 73
  fi
}

check_writable_dir '扫描报告目录' "$RESULT_ROOT"
check_writable_dir 'Scanner 状态目录' "$STATE_ROOT"

if [[ "${UPDATE_TEMPLATES:-true}" == "true" ]]; then
  check_writable_dir 'Nuclei 模板目录' "$TEMPLATE_ROOT"
  nuclei -ut >/tmp/nuclei-template-update.log 2>&1 || {
    echo '[scanner][WARN] nuclei 模板更新失败，继续使用缓存模板。' >&2
    tail -n 20 /tmp/nuclei-template-update.log >&2 || true
  }
fi

exec "$@"
