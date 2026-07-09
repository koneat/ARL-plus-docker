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

merge_unique() {
  local output="$1"
  shift
  {
    local path
    for path in "$@"; do
      [[ -f "$path" ]] && cat "$path"
    done
  } | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' >"$output"
}

merge_unique_limit() {
  local output="$1"
  local limit="$2"
  shift 2
  local temporary="${output}.all.$$"
  merge_unique "$temporary" "$@"
  head -n "$limit" "$temporary" >"$output"
  rm -f "$temporary"
}

case "$MODE" in
  fast)
    ENABLE_ALTERX_MODE="false"
    ENABLE_SECONDARY_CRAWL_MODE="false"
    ENABLE_FFUF_V2_MODE="false"
    PASSIVE_URL_LIMIT_MODE=2000
    ALTERX_LIMIT_MODE=0
    CONTENT_AUDIT_LIMIT_MODE=100
    V2_SCAN_URL_LIMIT_MODE=8000
    FFUF_V2_MAX_TARGETS_MODE=0
    SOURCEMAP_V2_LIMIT_MODE=1000
    ;;
  standard)
    ENABLE_ALTERX_MODE="true"
    ENABLE_SECONDARY_CRAWL_MODE="true"
    ENABLE_FFUF_V2_MODE="true"
    PASSIVE_URL_LIMIT_MODE=10000
    ALTERX_LIMIT_MODE=3000
    CONTENT_AUDIT_LIMIT_MODE=500
    V2_SCAN_URL_LIMIT_MODE=30000
    FFUF_V2_MAX_TARGETS_MODE=100
    SOURCEMAP_V2_LIMIT_MODE=5000
    ;;
  deep)
    ENABLE_ALTERX_MODE="true"
    ENABLE_SECONDARY_CRAWL_MODE="true"
    ENABLE_FFUF_V2_MODE="true"
    PASSIVE_URL_LIMIT_MODE=30000
    ALTERX_LIMIT_MODE=10000
    CONTENT_AUDIT_LIMIT_MODE=1500
    V2_SCAN_URL_LIMIT_MODE=75000
    FFUF_V2_MAX_TARGETS_MODE=300
    SOURCEMAP_V2_LIMIT_MODE=15000
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
ENABLE_FFUF_V2_EFFECTIVE="${ENABLE_FFUF_V2:-$ENABLE_FFUF_V2_MODE}"
ENABLE_SOURCEMAP_V2_EFFECTIVE="${ENABLE_SOURCEMAP_V2:-true}"
PASSIVE_URL_LIMIT="${PASSIVE_URL_LIMIT:-$PASSIVE_URL_LIMIT_MODE}"
ALTERX_LIMIT="${ALTERX_LIMIT:-$ALTERX_LIMIT_MODE}"
CONTENT_AUDIT_LIMIT="${CONTENT_AUDIT_LIMIT:-$CONTENT_AUDIT_LIMIT_MODE}"
V2_SCAN_URL_LIMIT="${V2_SCAN_URL_LIMIT:-$V2_SCAN_URL_LIMIT_MODE}"
FFUF_V2_MAX_TARGETS="${FFUF_V2_MAX_TARGETS:-$FFUF_V2_MAX_TARGETS_MODE}"
SOURCEMAP_V2_LIMIT="${SOURCEMAP_V2_LIMIT:-$SOURCEMAP_V2_LIMIT_MODE}"

mkdir -p "$OUT" "$OUT/ffuf"
for file in \
  urlfinder.jsonl urlfinder.txt gau.txt passive-urls.raw.txt passive-probe-targets.txt \
  passive-httpx.jsonl passive-live-urls.txt alterx.txt alterx.scoped.txt alterx.resolved.jsonl \
  tls-targets.txt tlsx.jsonl tls-san-domains.txt tls-findings.jsonl cdncheck.jsonl \
  enriched-domains.txt enriched-dnsx.jsonl enriched-httpx.jsonl enriched-live-urls.txt \
  katana.enriched.txt content-audit.jsonl content-endpoints.txt \
  sourcemap-v2-candidates.txt sourcemaps.v2.jsonl sourcemaps.v2.urls.txt \
  ffuf-v2-bases.txt ffuf-v2-hits.txt; do
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

  merge_unique_limit "$OUT/passive-urls.raw.txt" "$PASSIVE_URL_LIMIT" "$OUT/urlfinder.txt" "$OUT/gau.txt"
}

alterx_stage() {
  enabled "$ENABLE_ALTERX_EFFECTIVE" || return 0
  (( ALTERX_LIMIT > 0 )) || return 0
  [[ -s "$OUT/domains.all.txt" ]] || return 0

  local args=(
    -list "$OUT/domains.all.txt"
    -enrich
    -limit "$ALTERX_LIMIT"
    -silent
    -output "$OUT/alterx.txt"
  )
  if enabled "${ALTERX_CURATED_WORDS:-true}" && [[ -s /opt/scanner/wordlists/subdomain-environments.txt ]]; then
    args+=(-payload "word=/opt/scanner/wordlists/subdomain-environments.txt")
  fi
  alterx "${args[@]}" 2>"$OUT/alterx.log"

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
  merge_unique "$OUT/tls-targets.txt" "$OUT/domains.all.txt" "$OUT/open-services.txt"
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
  merge_unique "$OUT/cdncheck-targets.txt" "$OUT/domains.all.txt" "$OUT/ips.txt"
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
    -follow-host-redirects \
    -threads "${HTTPX_ENRICH_THREADS:-40}" \
    -rate-limit "${HTTPX_RATE_LIMIT:-150}" \
    -timeout 10 -retries 1 \
    -o "$OUT/enriched-httpx.jsonl"

  jq -r '.url // .input // empty' "$OUT/enriched-httpx.jsonl" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/enriched-live-urls.txt" || true

  merge_unique "$OUT/domains.all.txt.tmp" "$OUT/domains.all.txt" "$OUT/enriched-domains.txt"
  mv "$OUT/domains.all.txt.tmp" "$OUT/domains.all.txt"
  merge_unique "$OUT/live-urls.txt.tmp" "$OUT/live-urls.txt" "$OUT/enriched-live-urls.txt"
  mv "$OUT/live-urls.txt.tmp" "$OUT/live-urls.txt"
  cat "$OUT/httpx.jsonl" "$OUT/enriched-httpx.jsonl" 2>/dev/null >"$OUT/httpx.jsonl.tmp" || true
  mv "$OUT/httpx.jsonl.tmp" "$OUT/httpx.jsonl"
}

prepare_url_intelligence() {
  python3 /opt/scanner/asset_intelligence.py urls \
    "$OUT/domains.txt" "$OUT" \
    "$OUT/live-urls.txt" "$OUT/katana.txt" "$OUT/katana.enriched.txt" \
    "$OUT/passive-live-urls.txt" "$OUT/passive-urls.raw.txt" \
    "$OUT/ffuf-v2-hits.txt" "$OUT/sourcemaps.v2.urls.txt" "$OUT/content-endpoints.txt"
}

passive_probe_stage() {
  prepare_url_intelligence
  merge_unique_limit "$OUT/passive-probe-targets.txt" "$PASSIVE_URL_LIMIT" \
    "$OUT/urls-priority.txt" "$OUT/urls-intelligence-all.txt"
  [[ -s "$OUT/passive-probe-targets.txt" ]] || return 0

  httpx \
    -l "$OUT/passive-probe-targets.txt" \
    -silent -json \
    -status-code -title -tech-detect -web-server -ip -cname -cdn -location \
    -follow-host-redirects \
    -threads "${HTTPX_PASSIVE_THREADS:-50}" \
    -rate-limit "${HTTPX_RATE_LIMIT:-150}" \
    -timeout 10 -retries 1 \
    -o "$OUT/passive-httpx.jsonl"
  jq -r 'select((.status_code // 0) > 0) | .url // .input // empty' "$OUT/passive-httpx.jsonl" 2>/dev/null | \
    sed '/^[[:space:]]*$/d' | sort -u >"$OUT/passive-live-urls.txt" || true
  merge_unique "$OUT/live-urls.txt.tmp" "$OUT/live-urls.txt" "$OUT/passive-live-urls.txt"
  mv "$OUT/live-urls.txt.tmp" "$OUT/live-urls.txt"
}

secondary_crawl_stage() {
  enabled "$ENABLE_SECONDARY_CRAWL_EFFECTIVE" || return 0
  merge_unique_limit "$OUT/secondary-crawl-targets.txt" "${SECONDARY_CRAWL_TARGET_LIMIT:-500}" \
    "$OUT/enriched-live-urls.txt" "$OUT/passive-live-urls.txt"
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

sourcemap_v2_stage() {
  enabled "$ENABLE_SOURCEMAP_V2_EFFECTIVE" || return 0
  prepare_url_intelligence
  python3 - "$OUT/urls-js.txt" "$OUT/sourcemap-v2-candidates.txt" "$SOURCEMAP_V2_LIMIT" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

source = Path(sys.argv[1])
output = Path(sys.argv[2])
limit = int(sys.argv[3])
seen = set()
if source.is_file():
    for raw in source.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = raw.strip()
        if not value:
            continue
        try:
            parsed = urlsplit(value)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        lower = parsed.path.lower()
        if lower.endswith((".js", ".mjs")):
            seen.add(urlunsplit((parsed.scheme, parsed.netloc, parsed.path + ".map", "", "")))
        if len(seen) >= limit:
            break
output.write_text("".join(f"{item}\n" for item in sorted(seen)), encoding="utf-8")
PY
  [[ -s "$OUT/sourcemap-v2-candidates.txt" ]] || return 0
  httpx \
    -l "$OUT/sourcemap-v2-candidates.txt" \
    -silent -json \
    -match-code 200 \
    -match-string '"sources"' \
    -content-type -content-length \
    -threads 30 -rate-limit "${SOURCEMAP_V2_RATE_LIMIT:-60}" \
    -timeout 10 -retries 1 \
    -o "$OUT/sourcemaps.v2.jsonl"
  jq -r '.url // .input // empty' "$OUT/sourcemaps.v2.jsonl" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/sourcemaps.v2.urls.txt" || true
  {
    [[ -f "$OUT/sourcemaps.jsonl" ]] && cat "$OUT/sourcemaps.jsonl"
    cat "$OUT/sourcemaps.v2.jsonl"
  } | awk '!seen[$0]++' >"$OUT/sourcemaps.jsonl.tmp"
  mv "$OUT/sourcemaps.jsonl.tmp" "$OUT/sourcemaps.jsonl"
}

ffuf_v2_stage() {
  enabled "$ENABLE_FFUF_V2_EFFECTIVE" || return 0
  (( FFUF_V2_MAX_TARGETS > 0 )) || return 0
  python3 - "$OUT/enriched-live-urls.txt" "$OUT/passive-live-urls.txt" "$OUT/ffuf-v2-bases.txt" <<'PY'
import sys
from pathlib import Path
from urllib.parse import urlsplit

seen = set()
for source_name in sys.argv[1:-1]:
    source = Path(source_name)
    if not source.is_file():
        continue
    for raw in source.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = raw.strip()
        if not value:
            continue
        try:
            parsed = urlsplit(value)
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            seen.add(f"{parsed.scheme}://{parsed.netloc}")
Path(sys.argv[-1]).write_text("".join(f"{item}\n" for item in sorted(seen)), encoding="utf-8")
PY
  [[ -s "$OUT/ffuf-v2-bases.txt" ]] || return 0
  local count=0
  while IFS= read -r base; do
    [[ -n "$base" ]] || continue
    count=$((count + 1))
    (( count <= FFUF_V2_MAX_TARGETS )) || break
    local name
    name="$(printf '%s' "$base" | sha256sum | cut -d' ' -f1)"
    ffuf \
      -u "${base%/}/FUZZ" \
      -w /opt/scanner/wordlists/high-value-paths.txt \
      -ac \
      -mc 200,204,301,302,307,401,403,405,500 \
      -rate "${FFUF_V2_RATE:-${FFUF_RATE:-50}}" \
      -t 20 -timeout 10 -maxtime "${FFUF_V2_MAXTIME:-180}" \
      -of json -o "$OUT/ffuf/v2-${name}.json" -s || true
  done <"$OUT/ffuf-v2-bases.txt"

  find "$OUT/ffuf" -maxdepth 1 -type f -name 'v2-*.json' -print0 2>/dev/null | \
    xargs -0 -r jq -r '.results[]?.url // empty' 2>/dev/null | \
    sed '/^[[:space:]]*$/d' | sort -u >"$OUT/ffuf-v2-hits.txt" || true
}

content_audit_stage() {
  enabled "$ENABLE_CONTENT_AUDIT_EFFECTIVE" || return 0
  prepare_url_intelligence
  python3 /opt/scanner/content_audit.py \
    "$OUT" \
    "$OUT/urls-sensitive.txt" "$OUT/urls-js.txt" "$OUT/urls-api.txt" "$OUT/urls-priority.txt" \
    "$OUT/ffuf-v2-hits.txt" "$OUT/sourcemaps.v2.urls.txt" \
    --limit "$CONTENT_AUDIT_LIMIT" \
    --workers "${CONTENT_AUDIT_WORKERS:-10}" \
    --timeout "${CONTENT_AUDIT_TIMEOUT:-10}" \
    --max-bytes "${CONTENT_AUDIT_MAX_BYTES:-1048576}"
}

finalize_intelligence_stage() {
  prepare_url_intelligence
  merge_unique "$OUT/scan-urls.all.txt" \
    "$OUT/urls-priority.txt" \
    "$OUT/urls-api.txt" \
    "$OUT/urls-sensitive.txt" \
    "$OUT/ffuf-v2-hits.txt" \
    "$OUT/sourcemaps.v2.urls.txt" \
    "$OUT/content-endpoints.txt" \
    "$OUT/passive-live-urls.txt" \
    "$OUT/live-urls.txt" \
    "$OUT/katana.txt" \
    "$OUT/katana.enriched.txt"
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
    "sourcemap_v2_hits": count("sourcemaps.v2.urls.txt"),
    "ffuf_v2_hits": count("ffuf-v2-hits.txt"),
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
    echo "ffuf_v2_max_targets=${FFUF_V2_MAX_TARGETS}"
    echo "sourcemap_v2_limit=${SOURCEMAP_V2_LIMIT}"
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
if enabled "$ENABLE_SOURCEMAP_V2_EFFECTIVE"; then
  stage "新增与历史 JavaScript 的 Sourcemap 二次验证" sourcemap_v2_stage
fi
if enabled "$ENABLE_FFUF_V2_EFFECTIVE"; then
  stage "新增资产高价值路径二次枚举" ffuf_v2_stage
fi
if enabled "$ENABLE_CONTENT_AUDIT_EFFECTIVE"; then
  stage "内容级文件泄露验证与 JavaScript 接口挖掘" content_audit_stage
fi
stage "风险排序、去重与最终扫描目标生成" finalize_intelligence_stage

log "智能增强完成：最终扫描 URL $(line_count "$OUT/scan-urls.txt") 条"
