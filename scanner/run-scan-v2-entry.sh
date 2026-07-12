#!/usr/bin/env bash
set -Eeuo pipefail

REAL="/opt/scanner/run-scan-v2-real.sh"
TARGET_FILE="${1:-${TARGET_FILE:-/work/input/targets.txt}}"
MODE="${2:-${SCAN_MODE:-standard}}"
SCAN_ID_RAW="${SCAN_ID:-$(date +%Y%m%d-%H%M%S)}"
SCAN_ID="$(printf '%s' "$SCAN_ID_RAW" | tr -cd 'a-zA-Z0-9._-' | cut -c1-80)"
[[ -n "$SCAN_ID" ]] || SCAN_ID="$(date +%Y%m%d-%H%M%S)"
export SCAN_ID
OUT="/work/results/${SCAN_ID}"

log() {
  printf '[scanner-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

[[ -x "$REAL" ]] || { echo "missing scanner runner: $REAL" >&2; exit 1; }

if [[ -e /work/results/latest || -L /work/results/latest ]]; then
  previous="$(readlink -f /work/results/latest 2>/dev/null || true)"
  if [[ -n "$previous" && "$previous" != "$OUT" && -d "$previous" ]]; then
    export SCAN_DELTA_BASE="$previous"
  fi
fi

"$REAL" "$TARGET_FILE" "$MODE"

if enabled "${ENABLE_ACTIONABLE_INTELLIGENCE:-true}"; then
  log "开始：跨扫描器资产关联与可行动优先级"
  python3 /opt/scanner/intelligence_plus.py actionable "$OUT" || {
    rc=$?
    printf '%s\trc=%s\n' "可行动资产情报" "$rc" >>"$OUT/errors.log"
    log "WARN: 可行动资产情报失败，保留扫描结果并继续"
  }
fi

if enabled "${ENABLE_SCAN_DELTA:-true}"; then
  log "开始：与上一轮扫描做增量对比"
  python3 /opt/scanner/intelligence_plus.py delta "$OUT" /work/results || {
    rc=$?
    printf '%s\trc=%s\n' "扫描增量对比" "$rc" >>"$OUT/errors.log"
    log "WARN: 扫描增量对比失败，保留扫描结果并继续"
  }
fi

python3 /opt/scanner/summarize.py "$OUT"
python3 /opt/scanner/enhance_summary.py "$OUT"
python3 /opt/scanner/render_report.py "$OUT"
python3 /opt/scanner/intelligence_plus.py report "$OUT"
python3 /opt/scanner/finalize_quality.py "$OUT"

ln -sfn "$SCAN_ID" /work/results/latest
log "可行动资产：${OUT}/actionable-review.md"
log "API 操作：${OUT}/api-schema-findings.md"
log "扫描增量：${OUT}/scan-delta.md"
