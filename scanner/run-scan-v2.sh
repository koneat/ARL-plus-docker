#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_FILE="${1:-${TARGET_FILE:-/work/input/targets.txt}}"
MODE="${2:-${SCAN_MODE:-standard}}"
SCAN_ID_RAW="${SCAN_ID:-$(date +%Y%m%d-%H%M%S)}"
SCAN_ID="$(printf '%s' "$SCAN_ID_RAW" | tr -cd 'a-zA-Z0-9._-' | cut -c1-80)"
[[ -n "$SCAN_ID" ]] || SCAN_ID="$(date +%Y%m%d-%H%M%S)"
export SCAN_ID
OUT="/work/results/${SCAN_ID}"
SCOPE_TMP="/tmp/arl-scope-${SCAN_ID}"
NUCLEI_REQUESTED="${ENABLE_NUCLEI:-true}"

log() {
  printf '[scanner-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

cleanup() {
  rm -rf "$SCOPE_TMP"
}
trap cleanup EXIT

sanitize_active_targets() {
  local source="$OUT/scan-urls.all.txt"
  [[ -s "$source" ]] || source="$OUT/scan-urls.txt"
  [[ -f "$source" ]] || return 0

  local original_limit=0
  if [[ -f "$OUT/scan-urls.txt" ]]; then
    original_limit="$(grep -cve '^[[:space:]]*$' "$OUT/scan-urls.txt" 2>/dev/null || true)"
  fi
  local sanitized="$SCOPE_TMP/scan-urls.sanitized.txt"
  local stats="$SCOPE_TMP/scan-urls-sanitize-stats.json"

  python3 - "$source" "$sanitized" "$stats" <<'PY'
import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, "/opt/scanner")
from asset_intelligence import normalize_url, sanitize_query_pairs  # noqa: E402

source = Path(sys.argv[1])
output = Path(sys.argv[2])
stats_path = Path(sys.argv[3])
raw_lines = source.read_text(encoding="utf-8", errors="ignore").splitlines()
seen = set()
ordered = []
invalid = 0
redacted = 0
for raw in raw_lines:
    value = raw.strip()
    if not value:
        continue
    try:
        parsed = urlsplit(value)
        _, changed = sanitize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))
        redacted += int(changed)
    except ValueError:
        pass
    normalized = normalize_url(value)
    if not normalized:
        invalid += 1
        continue
    if normalized not in seen:
        seen.add(normalized)
        ordered.append(normalized)
output.write_text("".join(f"{value}\n" for value in ordered), encoding="utf-8")
stats_path.write_text(
    json.dumps(
        {"input": len(raw_lines), "output": len(ordered), "invalid": invalid, "redacted_query_values": redacted},
        ensure_ascii=False,
        indent=2,
    ) + "\n",
    encoding="utf-8",
)
PY

  cp "$sanitized" "$OUT/scan-urls.all.txt"
  if (( original_limit > 0 )); then
    head -n "$original_limit" "$sanitized" >"$OUT/scan-urls.txt"
  else
    : >"$OUT/scan-urls.txt"
  fi
  cp "$stats" "$OUT/final-target-sanitize-stats.json"
  log "主动扫描目标清洗完成：$(grep -cve '^[[:space:]]*$' "$OUT/scan-urls.txt" 2>/dev/null || true) 条"
}

case "$MODE" in
  fast|standard|deep) ;;
  *) echo "不支持的模式：${MODE}" >&2; exit 2 ;;
esac

mkdir -p "$OUT" "$SCOPE_TMP"
python3 /opt/scanner/prepare_targets.py "$TARGET_FILE" "$SCOPE_TMP"
cp "$SCOPE_TMP/domains.txt" "$OUT/scope-domains.txt"
cp "$SCOPE_TMP/ips.txt" "$OUT/scope-ips.txt"
cp "$SCOPE_TMP/cidrs.txt" "$OUT/scope-cidrs.txt"

log "第一阶段：运行稳定基础扫描链"
ENABLE_NUCLEI=false /opt/scanner/run-scan-uncover.sh "$TARGET_FILE" "$MODE"

cp "$OUT/domains.txt" "$OUT/domains.augmented-input.txt" 2>/dev/null || true
cp "$OUT/scope-domains.txt" "$OUT/domains.txt"

if enabled "${ENABLE_SCANNER_V2:-true}"; then
  log "第二阶段：运行资产与 URL 智能增强"
  /opt/scanner/run-intelligence.sh "$OUT" "$MODE"
else
  log "Scanner V2 智能增强已关闭"
fi

sanitize_active_targets

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
  echo "scope_domains=$(grep -cve '^[[:space:]]*$' "$OUT/scope-domains.txt" 2>/dev/null || true)"
  for tool in urlfinder gau alterx tlsx cdncheck; do
    printf '%s=' "$tool"
    "$tool" -version 2>&1 | head -n 1 || "$tool" --version 2>&1 | head -n 1 || true
  done
} >>"$OUT/manifest.txt"

ln -sfn "$SCAN_ID" /work/results/latest
log "扫描完成：${OUT}"
log "Markdown：${OUT}/summary.md"
log "HTML：${OUT}/report.html"
