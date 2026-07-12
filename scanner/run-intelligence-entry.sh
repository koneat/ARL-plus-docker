#!/usr/bin/env bash
set -Eeuo pipefail

REAL="/opt/scanner/run-intelligence-real.sh"
OUT="${1:?result directory required}"
MODE="${2:-standard}"
FEED_UPDATED=0

log() {
  printf '[scanner-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

append_urls() {
  local source_file="$1"
  [[ -s "$source_file" ]] || return 0
  {
    [[ -f "$OUT/scan-urls.all.txt" ]] && cat "$OUT/scan-urls.all.txt"
    cat "$source_file"
  } | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' >"$OUT/scan-urls.all.txt.tmp"
  mv "$OUT/scan-urls.all.txt.tmp" "$OUT/scan-urls.all.txt"
  FEED_UPDATED=1
}

refresh_scan_urls() {
  [[ "$FEED_UPDATED" -eq 1 ]] || return 0
  local limit="${V2_SCAN_URL_LIMIT:-}"
  if [[ -z "$limit" && -f "$OUT/manifest.txt" ]]; then
    limit="$(sed -n 's/^v2_scan_url_limit=//p' "$OUT/manifest.txt" | tail -n 1)"
  fi
  [[ "$limit" =~ ^[0-9]+$ ]] || case "$MODE" in
    fast) limit=8000 ;;
    standard) limit=30000 ;;
    deep) limit=75000 ;;
    *) limit=30000 ;;
  esac
  head -n "$limit" "$OUT/scan-urls.all.txt" >"$OUT/scan-urls.txt"
}

[[ -x "$REAL" ]] || { echo "missing intelligence runner: $REAL" >&2; exit 1; }
"$REAL" "$@"
touch "$OUT/errors.log"

if enabled "${ENABLE_EDGE_INTELLIGENCE:-true}"; then
  log "开始：GitHub 源码、Actions 与 FOFA 被动边缘系统情报"
  python3 /opt/scanner/edge_intelligence.py \
    "$OUT" \
    --github-max-queries "${EDGE_GITHUB_MAX_QUERIES:-36}" \
    --github-max-files "${EDGE_GITHUB_MAX_FILES:-80}" \
    --fofa-max-results "${EDGE_FOFA_MAX_RESULTS:-500}" \
    --timeout "${EDGE_INTEL_TIMEOUT:-12}" \
    --max-bytes "${EDGE_INTEL_MAX_BYTES:-1048576}" || {
      rc=$?
      printf '%s\trc=%s\n' "GitHub/Actions/FOFA 被动边缘情报" "$rc" >>"$OUT/errors.log"
      log "WARN: 被动边缘系统情报失败，保留原结果并继续"
    }
  if enabled "${EDGE_INTEL_FEED_SCAN:-false}"; then
    append_urls "$OUT/edge-urls.txt"
  fi
else
  log "GitHub/Actions/FOFA 被动边缘系统情报已关闭"
fi

if enabled "${ENABLE_API_SCHEMA_INTELLIGENCE:-true}"; then
  log "开始：OpenAPI/Swagger 文档解析与接口操作排序"
  python3 /opt/scanner/intelligence_plus.py api \
    "$OUT" \
    "$OUT/api-docs-endpoints.txt" \
    "$OUT/urls-api.txt" \
    "$OUT/urls-priority.txt" \
    "$OUT/live-urls.txt" \
    --scope-roots "$OUT/domains.txt" \
    --max-candidates "${API_SCHEMA_MAX_CANDIDATES:-200}" \
    --workers "${API_SCHEMA_WORKERS:-8}" \
    --timeout "${API_SCHEMA_TIMEOUT:-8}" \
    --max-bytes "${API_SCHEMA_MAX_BYTES:-4194304}" || {
      rc=$?
      printf '%s\trc=%s\n' "OpenAPI/Swagger 接口情报" "$rc" >>"$OUT/errors.log"
      log "WARN: OpenAPI/Swagger 接口情报失败，保留原结果并继续"
    }
  append_urls "$OUT/api-operation-urls.txt"
else
  log "OpenAPI/Swagger 接口情报已关闭"
fi

refresh_scan_urls

python3 - "$OUT" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
stats_path = root / "intelligence-stats.json"
try:
    stats = json.loads(stats_path.read_text(encoding="utf-8")) if stats_path.is_file() else {}
except Exception:
    stats = {}

def load(name):
    try:
        return json.loads((root / name).read_text(encoding="utf-8"))
    except Exception:
        return {}

api = load("api-schema-stats.json")
edge = load("edge-intelligence-stats.json")
stats["api_schema_documents"] = int(api.get("valid_documents", 0) or 0)
stats["api_operations"] = int(api.get("operations", 0) or 0)
stats["api_priority_operations"] = int(api.get("priority_operations", 0) or 0)
stats["api_schema_no_security"] = int(api.get("unauthenticated_schema_operations", 0) or 0)
stats["edge_assets"] = int(edge.get("assets", 0) or 0)
stats["edge_non_production_assets"] = int(edge.get("non_production_assets", 0) or 0)
stats["edge_github_config_files"] = int(edge.get("github_config_files", 0) or 0)
stats["edge_github_workflows"] = int(edge.get("github_workflows", 0) or 0)
stats["edge_fofa_results"] = int(edge.get("fofa_results", 0) or 0)
stats["edge_sensitive_indicators"] = int(edge.get("sensitive_indicators", 0) or 0)
stats["final_scan_urls"] = sum(
    1
    for line in (root / "scan-urls.txt").read_text(encoding="utf-8", errors="ignore").splitlines()
    if line.strip()
) if (root / "scan-urls.txt").is_file() else 0
stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

log "完成：被动边缘系统、OpenAPI/Swagger 与接口操作情报"
