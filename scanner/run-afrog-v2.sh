#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:?result directory required}"
MODE="${2:-standard}"
ERROR_LOG="${OUT}/errors.log"
TARGETS="$OUT/scan-urls.txt"

log() {
  printf '[afrog-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

case "$MODE" in
  fast) SEVERITY="high,critical" ;;
  standard) SEVERITY="medium,high,critical" ;;
  deep) SEVERITY="low,medium,high,critical" ;;
  *) echo "unsupported mode: ${MODE}" >&2; exit 2 ;;
esac
SEVERITY="${AFROG_SEVERITY_OVERRIDE:-$SEVERITY}"

mkdir -p "$OUT"
: >"$OUT/afrog.json"
: >"$OUT/afrog-v2.log"

if [[ ! -s "$TARGETS" ]]; then
  log "没有清洗后的 HTTP URL，跳过"
  exit 0
fi

args=(-T "$TARGETS" -S "$SEVERITY" -j "$OUT/afrog.json")
if find /opt/pocs/afrog -type f -name '*.yaml' -print -quit | grep -q .; then
  args+=(-P /opt/pocs/afrog)
fi

log "开始：使用清洗后的 URL 运行 Afrog"
if (cd "$OUT" && afrog "${args[@]}") > >(tee "$OUT/afrog-v2.log") 2>&1; then
  log "完成"
else
  rc=$?
  log "WARN: Afrog 失败 rc=${rc}，保留日志并继续"
  printf 'Afrog V2 清洗后复核\trc=%s\n' "$rc" >>"$ERROR_LOG"
fi
