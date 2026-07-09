#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:?result directory required}"
MODE="${2:-standard}"
ERROR_LOG="${OUT}/errors.log"

log() {
  printf '[scanner-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

warn() {
  log "WARN: $*" >&2
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

stage() {
  local name="$1"
  shift
  log "开始：${name}"
  if "$@"; then
    log "完成：${name}"
  else
    local rc=$?
    warn "${name} 失败，退出码 ${rc}；原扫描结果保留并继续"
    printf '%s\trc=%s\n' "$name" "$rc" >>"$ERROR_LOG"
  fi
}

line_count() {
  local path="$1"
  [[ -f "$path" ]] || { echo 0; return; }
  grep -cve '^[[:space:]]*$' "$path" 2>/dev/null || true
}

case "$MODE" in
  fast)
    ENABLE_ALTERX_MODE="false"
    ENABLE_SECONDARY_CRAWL_MODE="false"
    PASSIVE_URL_LIMIT_MODE=2000
    ALTERX_LIMIT_MODE=0
    CONTENT_AUDIT_LIMIT_MODE=100
    V2_SCAN_URL_LIMIT_MODE=8000
    ;;
  standard)
    ENABLE_ALTERX_MODE="true"
    ENABLE_SECONDARY_CRAWL_MODE="true"
    PASSIVE_URL_LIMIT_MODE=10000
    ALTERX_LIMIT_MODE=3000
    CONTENT_AUDIT_LIMIT_MODE=500
    V2_SCAN_URL_LIMIT_MODE=30000
    ;;
  deep)
    ENABLE_ALTERX_MODE="true"
    ENABLE_SECONDARY_CRAWL_MODE="true"
    PASSIVE_URL_LIMIT_MODE=30000
    ALTERX_LIMIT_MODE=10000
    CONTENT_AUDIT_LIMIT_MODE=1500
    V2_SCAN_URL_LIMIT_MODE=75000
    ;;
  *)
    echo "unsupported mode: ${MODE}" >&2
    exit 2
    ;;
esac

ENABLE_PASSIVE_URLS_EFFECTIVE="${ENABLE_PASSIVE_URLS:-true}"
ENABLE_TLSX_EFFECTIVE="${ENABLE_TLSX:-true}"
ENABLE_CDNCHECK_EFFECTIVE="${ENABLE_CDNCHECK:-true}"
ENABLE_ALTERX_EFFECTIVE="${ENABLE_ALTERX:-$ENABLE_ALTERX_MODE}"
ENABLE_CONTENT_AUDIT_EFFECTIVE="${ENABLE_CONTENT_AUDIT:-true}"
ENABLE_SECONDARY_CRAWL_EFFECTIVE="${ENABLE_SECONDARY_CRAWL:-$ENABLE_SECONDARY_CRAWL_MODE}"
PASSIVE_URL_LIMIT="${PASSIVE_URL_LIMIT:-$PASSIVE_URL_LIMIT_MODE}"
ALTERX_LIMIT="${ALTERX_LIMIT:-$ALTERX_LIMIT_MODE}"
CONTENT_AUDIT_LIMIT="${CONTENT_AUDIT_LIMIT:-$CONTENT_AUDIT_LIMIT_MODE}"
V2_SCAN_URL_LIMIT="${V2_SCAN_URL_LIMIT:-$V2_SCAN_URL_LIMIT_MODE}"

mkdir -p "$OUT"
for file in \
  urlfinder.jsonl urlfinder.txt gau.txt passive-urls.raw.txt passive-probe-targets.txt \
  passive-httpx.jsonl passive-live-urls.txt alterx.txt alterx.scoped.txt alterx.resolved.jsonl \
  tls-targets.txt tlsx.jsonl tls-san-domains.txt tls-findings.jsonl cdncheck.jsonl \
  enriched-domains.txt enriched-dnsx.jsonl enriched-httpx.jsonl enriched-live-urls.txt \
  katana.enriched.txt content-audit.jsonl content-endpoints.txt; do
  : >"$OUT/$file"
done

passive_urls_stage() {
  [[ -s "$OUT/domains.txt" ]] || return 0

  if command -v urlfinder >/dev/null 2>&1; then
    urlfinder \
      -list "$OUT/domains.txt" \
      -field-scope rdn \
      -rate-limit "${URLFINDER_RATE_LIMIT:-10}" \
      -max-time "${URLFINDER_MAX_TIME:-5}" \
      -silent -jsonl -collect-sources -disable-update-check \
      -o "$OUT/urlfinder.jsonl" \
      2>"$OUT/urlfinder.log" || true
    if [[ -s "$OUT/urlfinder.jsonl" ]]; then
      jq -r '.url // empty' "$OUT/urlfinder.jsonl" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/urlfinder.txt" || true
    fi
  fi

  if command -v gau >/dev/null 2>&1; then
    gau \
      --subs \
      --threads "${GAU_THREADS:-5}" \
      --timeout "${GAU_TIMEOUT:-30}" \
      --retries 2 \
      --providers "${GAU_PROVIDERS:-wayback,commoncrawl,otx,urlscan}" \
      --blacklist "${GAU_BLACKLIST:-png,jpg,jpeg,gif,webp,svg,ico,woff,woff2,ttf,eot,mp3,mp4,avi,mov,webm,css}" \
      --o "$OUT/gau.txt" \
      <"$OUT/domains.txt" 2>"$OUT/gau.log" || true
  fi

  cat "$OUT/urlfinder.txt" "$OUT/gau.txt" 2>/dev/null | \
    sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' | head -n "$PASSIVE_URL_LIMIT" >"$OUT/passive-urls.raw.txt"
}

alterx_stage() {
  enabled "$ENABLE_ALTERX_EFFECTIVE" || return 0
  (( ALTERX_LIMIT > 0 )) || return 0
  [[ -s "$OUT/domains.all.txt" ]] || return 0
  alterx \
    -list "$OUT/domains.all.txt" \
    -enrich \
    -limit "$ALTERX_LIMIT" \
    -silent \
    -output "$OUT/alterx.txt" \
    2>"$OUT/alterx.log"
  python3 /opt/scanner/asset_intelligence.py domains \
    "$OUT/domains.txt" "$OUT/alterx.scoped.txt" "$OUT/alterx.txt" \
    --rejected "$OUT/alterx.rejected.txt"
  [[ -s "$OUT/alterx.scoped.txt" ]] || return 0
  dnsx \
    -l "$OUT/alterx.scoped.txt" \
    -silent -a -resp -json \
    -rate-limit "${DNSX_ENRICH_RATE_LIMIT:-300}" \
    -o "$OUT/alterx.resolved.jsonl"
}

tlsx_stage() {
  [[ -s "$OUT/domains.all.txt" || -s "$OUT/open-services.txt" ]] || return 0
  cat "$OUT/domains.all.txt" "$OUT/open-services.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/tls-targets.txt"
  [[ -s "$OUT/tls-targets.txt" ]] || return 0
  tlsx \
    -list "$OUT/tls-targets.txt" \
    -san -cn -tls-version -cipher -jarm -probe-status \
    -concurrency "${TLSX_CONCURRENCY:-100}" \
    -timeout 5 -retry 1 \
    -json -silent -disable-update-check \
    -output "$OUT/tlsx.jsonl" \
    2>"$OUT/tlsx.log"
  python3 /opt/scanner/asset_intelligence.py tlsx \
    "$OUT/domains.txt" "$OUT/tlsx.jsonl" "$OUT"
}

cdncheck_stage() {
  cat "$OUT/domains.all.txt" "$OUT/ips.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/cdncheck-targets.txt"
  [[ -s "$OUT/cdncheck-targets.txt" ]] || return 0
  cdncheck \
    -input "$OUT/cdncheck-targets.txt" \
    -jsonl -resp -silent -disable-update-check \
    -output "$OUT/cdncheck.jsonl" \
    2>"$OUT/cdncheck.log"
}

enriched_domains_stage() {
  local alterx_hosts="$OUT/alterx.resolved.hosts.txt"
  if [[ -s "$OUT/alterx.resolved.jsonl" ]]; then
    jq -r '.host // .input // empty' "$OUT/alterx.resolved.jsonl" 2>/dev/null | sort -u >"$alterx_hosts" || true
  else
    : >"$alterx_hosts"
  fi

  python3 /opt/scanner/asset_intelligence.py domains \
    "$OUT/domains.txt" "$OUT/enriched-domains.txt" \
    "$OUT/tls-san-domains.txt" "$alterx_hosts" \
    --rejected "$OUT/enriched-domains.rejected.txt"

  [[ -s "$OUT/enriched-domains.txt" ]] || return 0
  dnsx \
    -l "$OUT/enriched-domains.txt" \
    -silent -a -resp -json \
    -rate-limit "${DNSX_ENRICH_RATE_LIMIT:-300}" \
    -o "$OUT/enriched-dnsx.jsonl" || true

  httpx \
    -l "$OUT/enriched-domains.txt" \
    -silent -json \
    -status-code -title -tech-detect -web-server -ip -cname -cdn -location \
    -follow-redirects \
    -threads "${HTTPX_ENRICH_THREADS:-40}" \
    -rate-limit "${HTTPX_RATE_LIMIT:-150}" \
    -timeout 10 -retries 1 \
    -o "$OUT/enriched-httpx.jsonl"

  jq -r '.url // .input // empty' "$OUT/enriched-httpx.jsonl" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/enriched-live-urls.txt" || true

  cat "$OUT/domains.all.txt" "$OUT/enriched-domains.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/domains.all.txt.tmp"
  mv "$OUT/domains.all.txt.tmp" "$OUT/domains.all.txt"
  cat "$OUT/live-urls.txt" "$OUT/enriched-live-urls.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/live-urls.txt.tmp"
  mv "$OUT/live-urls.txt.tmp" "$OUT/live-urls.txt"
  cat "$OUT/httpx.jsonl" "$OUT/enriched-httpx.jsonl" 2>/dev/null >"$OUT/httpx.jsonl.tmp"
  mv "$OUT/httpx.jsonl.tmp" "$OUT/httpx.jsonl"
}

passive_probe_stage() {
  python3 /opt/scanner/asset_intelligence.py urls \
    "$OUT/domains.txt" "$OUT" \
    "$OUT/live-urls.txt" "$OUT/katana.txt" "$OUT/passive-urls.raw.txt"

  cat "$OUT/urls-priority.txt" "$OUT/urls-intelligence-all.txt" 2>/dev/null | \
    awk '!seen[$0]++' | head -n "$PASSIVE_URL_LIMIT" >"$OUT/passive-probe-targets.txt"
  [[ -s "$OUT/passive-probe-targets.txt" ]] || return 0

  httpx \
    -l "$OUT/passive-probe-targets.txt" \
    -silent -json \
    -status-code -title -tech-detect -web-server -ip -cname -cdn -location \
    -follow-redirects \
    -threads "${HTTPX_PASSIVE_THREADS:-50}" \
    -rate-limit "${HTTPX_RATE_LIMIT:-150}" \
    -timeout 10 -retries 1 \
    -o "$OUT/passive-httpx.jsonl"
  jq -r 'select((.status_code // 0) > 0) | .url // .input // empty' "$OUT/passive-httpx.jsonl" 2>/dev/null | \
    sed '/^[[:space:]]*$/d' | sort -u >"$OUT/passive-live-urls.txt" || true
  cat "$OUT/live-urls.txt" "$OUT/passive-live-urls.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/live-urls.txt.tmp"
  mv "$OUT/live-urls.txt.tmp" "$OUT/live-urls.txt"
}

secondary_crawl_stage() {
  enabled "$ENABLE_SECONDARY_CRAWL_EFFECTIVE" || return 0
  cat "$OUT/enriched-live-urls.txt" "$OUT/passive-live-urls.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u | head -n "${SECONDARY_CRAWL_TARGET_LIMIT:-500}" >"$OUT/secondary-crawl-targets.txt"
  [[ -s "$OUT/secondary-crawl-targets.txt" ]] || return 0
  local depth=2
  [[ "$MODE" == "deep" ]] && depth=4
  katana \
    -list "$OUT/secondary-crawl-targets.txt" \
    -silent -depth "$depth" \
    -field-scope rdn \
    -ignore-query-params -filter-similar \
    -js-crawl -known-files all \
    -concurrency 10 -parallelism 10 \
    -timeout 10 -retry 1 \
    -o "$OUT/katana.enriched.txt"
}

content_audit_stage() {
  enabled "$ENABLE_CONTENT_AUDIT_EFFECTIVE" || return 0
  python3 /opt/scanner/asset_intelligence.py urls \
    "$OUT/domains.txt" "$OUT" \
    "$OUT/live-urls.txt" "$OUT/katana.txt" "$OUT/katana.enriched.txt" \
    "$OUT/passive-live-urls.txt" "$OUT/passive-urls.raw.txt"
  python3 /opt/scanner/content_audit.py \
    "$OUT" \
    "$OUT/urls-sensitive.txt" "$OUT/urls-js.txt" "$OUT/urls-api.txt" "$OUT/urls-priority.txt" \
    --limit "$CONTENT_AUDIT_LIMIT" \
    --workers "${CONTENT_AUDIT_WORKERS:-10}" \
    --timeout "${CONTENT_AUDIT_TIMEOUT:-10}" \
    --max-bytes "${CONTENT_AUDIT_MAX_BYTES:-1048576}"
}

finalize_intelligence_stage() {
  python3 /opt/scanner/asset_intelligence.py urls \
    "$OUT/domains.txt" "$OUT" \
    "$OUT/live-urls.txt" "$OUT/katana.txt" "$OUT/katana.enriched.txt" \
    "$OUT/passive-live-urls.txt" "$OUT/passive-urls.raw.txt" "$OUT/content-endpoints.txt"

  cat \
    "$OUT/urls-priority.txt" \
    "$OUT/urls-api.txt" \
    "$OUT/urls-sensitive.txt" \
    "$OUT/content-endpoints.txt" \
    "$OUT/passive-live-urls.txt" \
    "$OUT/live-urls.txt" \
    "$OUT/katana.txt" \
    "$OUT/katana.enriched.txt" 2>/dev/null | \
    sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' >"$OUT/scan-urls.all.txt"
  head -n "$V2_SCAN_URL_LIMIT" "$OUT/scan-urls.all.txt" >"$OUT/scan-urls.txt"

  python3 - "$OUT" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
def count(name: str) -> int:
    path = root / name
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())

stats = {
    "urlfinder_urls": count("urlfinder.txt"),
    "gau_urls": count("gau.txt"),
    "passive_urls": count("passive-urls.raw.txt"),
    "passive_live_urls": count("passive-live-urls.txt"),
    "alterx_candidates": count("alterx.scoped.txt"),
    "alterx_resolved": count("alterx.resolved.jsonl"),
    "tls_san_domains": count("tls-san-domains.txt"),
    "enriched_domains": count("enriched-domains.txt"),
    "secondary_crawl_urls": count("katana.enriched.txt"),
    "priority_urls": count("urls-priority.txt"),
    "api_urls": count("urls-api.txt"),
    "parameterized_urls": count("urls-params.txt"),
    "sensitive_urls": count("urls-sensitive.txt"),
    "javascript_urls": count("urls-js.txt"),
    "content_endpoints": count("content-endpoints.txt"),
    "final_scan_urls": count("scan-urls.txt"),
}
(root / "intelligence-stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

  {
    echo "scanner_v2=true"
    echo "passive_url_limit=${PASSIVE_URL_LIMIT}"
    echo "alterx_limit=${ALTERX_LIMIT}"
    echo "content_audit_limit=${CONTENT_AUDIT_LIMIT}"
    echo "v2_scan_url_limit=${V2_SCAN_URL_LIMIT}"
  } >>"$OUT/manifest.txt"
}

if enabled "$ENABLE_PASSIVE_URLS_EFFECTIVE"; then
  stage "历史与被动 URL 聚合（urlfinder/gau）" passive_urls_stage
fi
if enabled "$ENABLE_ALTERX_EFFECTIVE"; then
  stage "基于已发现资产的子域名排列与解析（alterx/dnsx）" alterx_stage
fi
if enabled "$ENABLE_TLSX_EFFECTIVE"; then
  stage "TLS 证书、SAN 与指纹扩展（tlsx）" tlsx_stage
fi
if enabled "$ENABLE_CDNCHECK_EFFECTIVE"; then
  stage "CDN、云与 WAF 分类（cdncheck）" cdncheck_stage
fi
stage "新域名存活验证与资产回灌" enriched_domains_stage
if enabled "$ENABLE_PASSIVE_URLS_EFFECTIVE"; then
  stage "历史 URL 存活与技术栈验证" passive_probe_stage
fi
if enabled "$ENABLE_SECONDARY_CRAWL_EFFECTIVE"; then
  stage "新增资产二次爬取" secondary_crawl_stage
fi
if enabled "$ENABLE_CONTENT_AUDIT_EFFECTIVE"; then
  stage "内容级文件泄露验证与 JavaScript 接口挖掘" content_audit_stage
fi
stage "风险排序、去重与最终扫描目标生成" finalize_intelligence_stage

log "智能增强完成：最终扫描 URL $(line_count "$OUT/scan-urls.txt") 条"
