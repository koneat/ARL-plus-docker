#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_FILE="${1:-${TARGET_FILE:-/work/input/targets.txt}}"
MODE="${2:-${SCAN_MODE:-standard}}"
SCAN_ID_RAW="${SCAN_ID:-$(date +%Y%m%d-%H%M%S)}"
SCAN_ID="$(printf '%s' "$SCAN_ID_RAW" | tr -cd 'a-zA-Z0-9._-' | cut -c1-80)"
[[ -n "$SCAN_ID" ]] || SCAN_ID="$(date +%Y%m%d-%H%M%S)"
OUT="/work/results/${SCAN_ID}"
ERROR_LOG="${OUT}/errors.log"

log() {
  printf '[scanner][%s] %s\n' "$(date '+%F %T')" "$*"
}

warn() {
  log "WARN: $*" >&2
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

run_stage() {
  local name="$1"
  shift
  log "开始：${name}"
  if "$@"; then
    log "完成：${name}"
  else
    local rc=$?
    warn "${name} 失败，退出码 ${rc}；继续后续阶段"
    printf '%s\trc=%s\n' "$name" "$rc" >>"$ERROR_LOG"
  fi
}

mkdir -p "$OUT" "$OUT/ffuf"
: >"$ERROR_LOG"
cp "$TARGET_FILE" "$OUT/targets.source.txt"
python3 /opt/scanner/prepare_targets.py "$TARGET_FILE" "$OUT"

case "$MODE" in
  fast)
    TOP_PORTS="100"
    SUBFINDER_ALL="false"
    SUBFINDER_RECURSIVE="false"
    KATANA_DEPTH="2"
    KATANA_JS="false"
    NUCLEI_SEVERITY="high,critical"
    AFROG_SEVERITY="high,critical"
    NUCLEI_CONCURRENCY="20"
    HTTPX_THREADS="30"
    ENABLE_FFUF_MODE="false"
    ;;
  standard)
    TOP_PORTS="1000"
    SUBFINDER_ALL="false"
    SUBFINDER_RECURSIVE="false"
    KATANA_DEPTH="3"
    KATANA_JS="true"
    NUCLEI_SEVERITY="medium,high,critical"
    AFROG_SEVERITY="medium,high,critical"
    NUCLEI_CONCURRENCY="30"
    HTTPX_THREADS="50"
    ENABLE_FFUF_MODE="true"
    ;;
  deep)
    TOP_PORTS="1000"
    SUBFINDER_ALL="true"
    SUBFINDER_RECURSIVE="true"
    KATANA_DEPTH="5"
    KATANA_JS="true"
    NUCLEI_SEVERITY="low,medium,high,critical"
    AFROG_SEVERITY="low,medium,high,critical"
    NUCLEI_CONCURRENCY="40"
    HTTPX_THREADS="70"
    ENABLE_FFUF_MODE="true"
    ;;
  *)
    echo "不支持的模式: ${MODE}；可选 fast、standard、deep" >&2
    exit 2
    ;;
esac

TOP_PORTS="${TOP_PORTS_OVERRIDE:-$TOP_PORTS}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY_OVERRIDE:-$NUCLEI_SEVERITY}"
AFROG_SEVERITY="${AFROG_SEVERITY_OVERRIDE:-$AFROG_SEVERITY}"

{
  echo "scan_id=${SCAN_ID}"
  echo "mode=${MODE}"
  echo "started_at=$(date -Iseconds)"
  echo "target_file=${TARGET_FILE}"
  echo "top_ports=${TOP_PORTS}"
  echo "nuclei_severity=${NUCLEI_SEVERITY}"
} >"$OUT/manifest.txt"

subfinder_stage() {
  : >"$OUT/subfinder.txt"
  [[ -s "$OUT/domains.txt" ]] || return 0
  local args=(-dL "$OUT/domains.txt" -silent -o "$OUT/subfinder.txt")
  enabled "$SUBFINDER_ALL" && args+=(-all)
  enabled "$SUBFINDER_RECURSIVE" && args+=(-recursive)
  subfinder "${args[@]}"
}

if enabled "${ENABLE_SUBFINDER:-true}"; then
  run_stage "被动子域名收集 subfinder" subfinder_stage
else
  : >"$OUT/subfinder.txt"
fi

cat "$OUT/domains.txt" "$OUT/subfinder.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/domains.all.txt"
cat "$OUT/hosts.txt" "$OUT/domains.all.txt" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/hosts.all.txt"

dnsx_stage() {
  : >"$OUT/dnsx.jsonl"
  [[ -s "$OUT/domains.all.txt" ]] || return 0
  dnsx -l "$OUT/domains.all.txt" -silent -a -resp -json -o "$OUT/dnsx.jsonl"
}
run_stage "DNS 解析与存活验证 dnsx" dnsx_stage

if [[ -s "$OUT/dnsx.jsonl" ]]; then
  jq -r '.host // .input // empty' "$OUT/dnsx.jsonl" | sort -u >"$OUT/dnsx.hosts.txt" || true
else
  : >"$OUT/dnsx.hosts.txt"
fi
cat "$OUT/hosts.all.txt" "$OUT/dnsx.hosts.txt" | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/portscan.targets.txt"

naabu_stage() {
  : >"$OUT/naabu.jsonl"
  [[ -s "$OUT/portscan.targets.txt" ]] || return 0
  local args=(
    -list "$OUT/portscan.targets.txt"
    -scan-type c
    -rate "${NAABU_RATE:-500}"
    -retries 1
    -timeout 3000
    -silent
    -json
    -o "$OUT/naabu.jsonl"
  )
  if [[ -n "${CUSTOM_PORTS:-}" ]]; then
    args+=(-p "$CUSTOM_PORTS")
  else
    args+=(-top-ports "$TOP_PORTS")
  fi
  naabu "${args[@]}"
}

if enabled "${ENABLE_NAABU:-true}"; then
  run_stage "TCP 端口发现 naabu（connect scan）" naabu_stage
else
  : >"$OUT/naabu.jsonl"
fi

if [[ -s "$OUT/naabu.jsonl" ]]; then
  jq -r 'select(.host and .port) | "\(.host):\(.port)"' "$OUT/naabu.jsonl" | sort -u >"$OUT/open-services.txt" || true
else
  : >"$OUT/open-services.txt"
fi

cat "$OUT/urls.seed.txt" "$OUT/hosts.all.txt" "$OUT/open-services.txt" 2>/dev/null | \
  sed '/^[[:space:]]*$/d' | sort -u >"$OUT/httpx.targets.txt"

httpx_stage() {
  : >"$OUT/httpx.jsonl"
  [[ -s "$OUT/httpx.targets.txt" ]] || return 0
  httpx \
    -l "$OUT/httpx.targets.txt" \
    -silent -json \
    -status-code -title -tech-detect -web-server -ip -cname -cdn -location \
    -follow-redirects \
    -threads "$HTTPX_THREADS" \
    -rate-limit "${HTTPX_RATE_LIMIT:-150}" \
    -timeout 10 -retries 1 \
    -o "$OUT/httpx.jsonl"
}
run_stage "HTTP 存活、标题、指纹与 CDN 探测 httpx" httpx_stage

if [[ -s "$OUT/httpx.jsonl" ]]; then
  jq -r '.url // .input // empty' "$OUT/httpx.jsonl" | sed '/^[[:space:]]*$/d' | sort -u >"$OUT/live-urls.txt" || true
else
  : >"$OUT/live-urls.txt"
fi

katana_stage() {
  : >"$OUT/katana.txt"
  [[ -s "$OUT/live-urls.txt" ]] || return 0
  local args=(
    -list "$OUT/live-urls.txt"
    -silent
    -depth "$KATANA_DEPTH"
    -concurrency 10
    -parallelism 10
    -timeout 10
    -retry 1
    -o "$OUT/katana.txt"
  )
  if enabled "$KATANA_JS"; then
    args+=(-js-crawl -known-files all)
  fi
  katana "${args[@]}"
}

if enabled "${ENABLE_KATANA:-true}"; then
  run_stage "URL、JS 与已知文件爬取 katana" katana_stage
else
  : >"$OUT/katana.txt"
fi

cat "$OUT/live-urls.txt" "$OUT/katana.txt" 2>/dev/null | \
  sed '/^[[:space:]]*$/d' | sort -u >"$OUT/scan-urls.txt"

nuclei_official_stage() {
  : >"$OUT/nuclei.official.jsonl"
  [[ -s "$OUT/scan-urls.txt" ]] || return 0
  nuclei \
    -l "$OUT/scan-urls.txt" \
    -silent -jsonl \
    -severity "$NUCLEI_SEVERITY" \
    -rate-limit "${NUCLEI_RATE_LIMIT:-120}" \
    -concurrency "$NUCLEI_CONCURRENCY" \
    -bulk-size 25 \
    -timeout 10 -retries 1 \
    -stats -stats-interval 60 -duc \
    -o "$OUT/nuclei.official.jsonl"
}

nuclei_custom_stage() {
  : >"$OUT/nuclei.custom.jsonl"
  [[ -s "$OUT/scan-urls.txt" ]] || return 0
  find /opt/pocs/nuclei -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q . || return 0
  nuclei \
    -l "$OUT/scan-urls.txt" \
    -t /opt/pocs/nuclei \
    -silent -jsonl \
    -severity "$NUCLEI_SEVERITY" \
    -rate-limit "${NUCLEI_RATE_LIMIT:-120}" \
    -concurrency "$NUCLEI_CONCURRENCY" \
    -bulk-size 25 \
    -timeout 10 -retries 1 -duc \
    -o "$OUT/nuclei.custom.jsonl"
}

if enabled "${ENABLE_NUCLEI:-true}"; then
  run_stage "Nuclei 官方模板扫描" nuclei_official_stage
  run_stage "Nuclei 自定义模板扫描" nuclei_custom_stage
else
  : >"$OUT/nuclei.official.jsonl"
  : >"$OUT/nuclei.custom.jsonl"
fi
cat "$OUT/nuclei.official.jsonl" "$OUT/nuclei.custom.jsonl" 2>/dev/null >"$OUT/nuclei.jsonl"

afrog_stage() {
  : >"$OUT/afrog.json"
  [[ -s "$OUT/live-urls.txt" ]] || return 0
  local args=(-T "$OUT/live-urls.txt" -S "$AFROG_SEVERITY" -j "$OUT/afrog.json")
  if find /opt/pocs/afrog -type f -name '*.yaml' -print -quit | grep -q .; then
    args+=(-P /opt/pocs/afrog)
  fi
  (cd "$OUT" && afrog "${args[@]}")
}

if enabled "${ENABLE_AFROG:-true}"; then
  run_stage "afrog 高价值 PoC 复核" afrog_stage
else
  : >"$OUT/afrog.json"
fi

ffuf_stage() {
  [[ -s "$OUT/live-urls.txt" ]] || return 0
  python3 - "$OUT/live-urls.txt" "$OUT/ffuf-bases.txt" <<'PY'
import sys
from urllib.parse import urlsplit

seen = set()
with open(sys.argv[1], encoding="utf-8", errors="ignore") as src, open(sys.argv[2], "w", encoding="utf-8") as dst:
    for line in src:
        value = line.strip()
        if not value:
            continue
        p = urlsplit(value)
        if p.scheme not in {"http", "https"} or not p.netloc:
            continue
        base = f"{p.scheme}://{p.netloc}"
        if base not in seen:
            seen.add(base)
            dst.write(base + "\n")
PY

  local count=0
  while IFS= read -r base; do
    [[ -n "$base" ]] || continue
    count=$((count + 1))
    if (( count > ${FFUF_MAX_TARGETS:-100} )); then
      break
    fi
    local name
    name="$(printf '%s' "$base" | sha256sum | cut -d' ' -f1)"
    ffuf \
      -u "${base%/}/FUZZ" \
      -w /opt/scanner/wordlists/high-value-paths.txt \
      -ac \
      -mc 200,204,301,302,307,401,403,405,500 \
      -rate "${FFUF_RATE:-50}" \
      -t 20 -timeout 10 -maxtime 180 \
      -of json -o "$OUT/ffuf/${name}.json" -s || true
  done <"$OUT/ffuf-bases.txt"
}

if enabled "${ENABLE_FFUF:-true}" && enabled "$ENABLE_FFUF_MODE"; then
  run_stage "高价值路径与配置泄露探测 ffuf" ffuf_stage
fi

python3 /opt/scanner/summarize.py "$OUT"

{
  echo
  echo "completed_at=$(date -Iseconds)"
  for tool in subfinder dnsx naabu httpx katana nuclei afrog ffuf nmap; do
    printf '%s=' "$tool"
    "$tool" -version 2>&1 | head -n 1 || "$tool" -V 2>&1 | head -n 1 || true
  done
} >>"$OUT/manifest.txt"

ln -sfn "$SCAN_ID" /work/results/latest
log "扫描完成：${OUT}"
log "汇总报告：${OUT}/summary.md"
