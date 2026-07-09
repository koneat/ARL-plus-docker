#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_FILE="${1:-${TARGET_FILE:-/work/input/targets.txt}}"
MODE="${2:-${SCAN_MODE:-standard}}"
SCAN_ID_RAW="${SCAN_ID:-$(date +%Y%m%d-%H%M%S)}"
SCAN_ID="$(printf '%s' "$SCAN_ID_RAW" | tr -cd 'a-zA-Z0-9._-' | cut -c1-80)"
[[ -n "$SCAN_ID" ]] || SCAN_ID="$(date +%Y%m%d-%H%M%S)"
export SCAN_ID
OUT="/work/results/${SCAN_ID}"
NUCLEI_REQUESTED="${ENABLE_NUCLEI:-true}"

log() {
  printf '[scanner-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

case "$MODE" in
  fast|standard|deep) ;;
  *) echo "不支持的模式：${MODE}" >&2; exit 2 ;;
esac

mkdir -p "$OUT"
log "第一阶段：运行稳定基础扫描链"
ENABLE_NUCLEI=false /opt/scanner/run-scan-uncover.sh "$TARGET_FILE" "$MODE"

if enabled "${ENABLE_SCANNER_V2:-true}"; then
  log "第二阶段：运行资产与 URL 智能增强"
  /opt/scanner/run-intelligence.sh "$OUT" "$MODE"
else
  log "Scanner V2 智能增强已关闭"
fi

if enabled "$NUCLEI_REQUESTED"; then
  log "第三阶段：运行协议分流 Nuclei V2"
  /opt/scanner/run-nuclei-v2.sh "$OUT" "$MODE"
else
  log "Nuclei 已关闭"
  python3 /opt/scanner/summarize.py "$OUT"
fi

python3 /opt/scanner/enhance_summary.py "$OUT"
python3 /opt/scanner/render_report.py "$OUT"

{
  echo
  echo "scanner_v2_completed_at=$(date -Iseconds)"
  for tool in urlfinder gau alterx tlsx cdncheck; do
    printf '%s=' "$tool"
    "$tool" -version 2>&1 | head -n 1 || "$tool" --version 2>&1 | head -n 1 || true
  done
} >>"$OUT/manifest.txt"

ln -sfn "$SCAN_ID" /work/results/latest
log "扫描完成：${OUT}"
log "Markdown：${OUT}/summary.md"
log "HTML：${OUT}/report.html"
