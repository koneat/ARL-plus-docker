#!/usr/bin/env bash
set -Eeuo pipefail

RESULT_ROOT="${SCANNER_V2_RESULT_ROOT:-/work/results}"
STATE_ROOT="${SCANNER_V2_STATE_ROOT:-/root/.config/scanner-api}"
LOG_ROOT="${SCANNER_V2_LOG_ROOT:-${STATE_ROOT}/logs}"
INPUT_ROOT="${SCANNER_V2_INPUT_ROOT:-/work/input/api}"
TEMPLATE_ROOT="${NUCLEI_TEMPLATE_DIR:-/root/nuclei-templates}"
TEMPLATE_UPDATE_TIMEOUT="${NUCLEI_TEMPLATE_UPDATE_TIMEOUT:-300}"

[[ "$TEMPLATE_UPDATE_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || TEMPLATE_UPDATE_TIMEOUT=300

mkdir -p \
  "$RESULT_ROOT" \
  "$STATE_ROOT" \
  "$LOG_ROOT" \
  "$INPUT_ROOT" \
  "$TEMPLATE_ROOT" \
  /opt/pocs/nuclei \
  /opt/pocs/afrog

check_writable_dir() {
  local name="$1"
  local directory="$2"
  local probe="${directory}/.arl-write-probe.$$"

  if ! (umask 077; : >"$probe" && rm -f "$probe"); then
    echo "[scanner][FATAL] ${name} 不可写：${directory}" >&2
    echo "[scanner][FATAL] 当前安全配置不会绕过宿主机目录权限。" >&2
    echo "[scanner][FATAL] 请修正对应宿主机目录的属主和写权限。" >&2
    ls -ld "$directory" >&2 || true
    stat -c '[scanner][FATAL] mode=%a uid=%u gid=%g path=%n' "$directory" >&2 || true
    exit 73
  fi
}

check_writable_dir '扫描报告目录' "$RESULT_ROOT"
check_writable_dir 'Scanner 状态目录' "$STATE_ROOT"
check_writable_dir 'Scanner 日志目录' "$LOG_ROOT"
check_writable_dir 'Scanner 输入目录' "$INPUT_ROOT"

if [[ "${UPDATE_TEMPLATES:-true}" == "true" ]]; then
  check_writable_dir 'Nuclei 模板目录' "$TEMPLATE_ROOT"
  set +e
  timeout "${TEMPLATE_UPDATE_TIMEOUT}s" nuclei -ut >/tmp/nuclei-template-update.log 2>&1
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    if [[ "$rc" -eq 124 ]]; then
      echo "[scanner][WARN] nuclei 模板更新超过 ${TEMPLATE_UPDATE_TIMEOUT}s，继续使用缓存模板。" >&2
    else
      echo "[scanner][WARN] nuclei 模板更新失败 rc=${rc}，继续使用缓存模板。" >&2
    fi
    tail -n 20 /tmp/nuclei-template-update.log >&2 || true
  fi
fi

exec "$@"
