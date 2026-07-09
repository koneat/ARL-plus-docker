#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:?result directory required}"
MODE="${2:-standard}"
ERROR_LOG="${OUT}/errors.log"
NUCLEI_EXTRA_TARGETS="/tmp/arl-nuclei-v2-extra-$$.txt"
trap 'rm -f "$NUCLEI_EXTRA_TARGETS"' EXIT

log() {
  printf '[nuclei-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

resolve_policy() {
  local policy="${NUCLEI_POLICY:-auto}"
  if [[ "$policy" == "auto" ]]; then
    case "$MODE" in
      fast) policy="safe" ;;
      standard) policy="balanced" ;;
      deep) policy="deep" ;;
    esac
  fi
  case "$policy" in
    off|safe|balanced|exposure|deep) printf '%s' "$policy" ;;
    *) printf 'balanced' ;;
  esac
}

resolve_severity() {
  if [[ -n "${NUCLEI_SEVERITY_OVERRIDE:-}" ]]; then
    printf '%s' "$NUCLEI_SEVERITY_OVERRIDE"
    return
  fi
  case "$MODE" in
    fast) printf 'high,critical' ;;
    standard) printf 'medium,high,critical' ;;
    deep) printf 'low,medium,high,critical' ;;
  esac
}

ensure_templates() {
  local template_dir="${NUCLEI_TEMPLATE_DIR:-/root/nuclei-templates}"
  local minimum="${NUCLEI_TEMPLATE_MIN_COUNT:-50}"
  local count=0
  [[ -d "$template_dir" ]] && count="$(find "$template_dir" -type f \( -name '*.yaml' -o -name '*.yml' \) | wc -l | tr -d ' ')"
  if (( count < minimum )); then
    log "模板数量 ${count}，尝试更新"
    nuclei -ut >"$OUT/nuclei-template-update.log" 2>&1 || true
    count="$(find "$template_dir" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l | tr -d ' ')"
  fi
  {
    echo "enabled=true"
    echo "template_dir=${template_dir}"
    echo "template_count=${count}"
    echo "minimum_expected=${minimum}"
  } >"$OUT/nuclei-template-status.txt"
  (( count > 0 )) || log "WARN: 官方模板目录为空"
}

run_pass() {
  local name="$1"
  local output="$2"
  local logfile="$3"
  local targets="$4"
  local severity="$5"
  shift 5
  : >"$output"
  : >"$logfile"
  [[ -s "$targets" ]] || return 0
  log "开始：${name}"
  if nuclei \
    -l "$targets" \
    -silent -jsonl \
    -severity "$severity" \
    -exclude-tags "${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}" \
    -rate-limit "${NUCLEI_RATE_LIMIT:-120}" \
    -concurrency "${NUCLEI_EXTRA_CONCURRENCY:-20}" \
    -bulk-size "${NUCLEI_BULK_SIZE:-20}" \
    -timeout "${NUCLEI_TIMEOUT:-10}" -retries 1 -duc \
    -o "$output" \
    "$@" 2> >(tee "$logfile" >&2); then
    log "完成：${name}"
  else
    local rc=$?
    log "WARN: ${name} 失败 rc=${rc}"
    printf '%s\trc=%s\n' "$name" "$rc" >>"$ERROR_LOG"
  fi
}

mkdir -p "$OUT"
ensure_templates

python3 /opt/scanner/extract_api_surface.py \
  "$OUT" \
  "$OUT/live-urls.txt" "$OUT/katana.txt" "$OUT/katana.enriched.txt" \
  "$OUT/content-endpoints.txt" "$OUT/urls-api.txt" "$OUT/sourcemap-candidates.txt"

cat \
  "$OUT/urls-api.txt" \
  "$OUT/api-endpoints.txt" \
  "$OUT/api-docs-endpoints.txt" \
  "$OUT/webhook-endpoints.txt" \
  "$OUT/content-endpoints.txt" 2>/dev/null | \
  sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' >"$NUCLEI_EXTRA_TARGETS"

POLICY="$(resolve_policy)"
GENERAL_SEVERITY="$(resolve_severity)"
EXTRA_SEVERITY="${NUCLEI_EXTRA_SEVERITY:-info,low,medium,high,critical}"

{
  echo "nuclei_v2=true"
  echo "nuclei_policy=${POLICY}"
  echo "nuclei_general_severity=${GENERAL_SEVERITY}"
  echo "nuclei_extra_severity=${EXTRA_SEVERITY}"
  echo "nuclei_exclude_tags=${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}"
} >>"$OUT/manifest.txt"

for name in official custom automatic exposure api network dns; do
  : >"$OUT/nuclei.${name}.jsonl"
  : >"$OUT/nuclei.${name}.log"
done

run_pass \
  "Nuclei 官方模板全量扫描" \
  "$OUT/nuclei.official.jsonl" "$OUT/nuclei.official.log" \
  "$OUT/scan-urls.txt" "$GENERAL_SEVERITY"

if find /opt/pocs/nuclei -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .; then
  run_pass \
    "Nuclei 自定义模板扫描" \
    "$OUT/nuclei.custom.jsonl" "$OUT/nuclei.custom.log" \
    "$OUT/scan-urls.txt" "$GENERAL_SEVERITY" \
    -t /opt/pocs/nuclei
fi

if [[ "$POLICY" != "off" ]]; then
  if [[ "$POLICY" == "balanced" || "$POLICY" == "deep" ]] && enabled "${ENABLE_NUCLEI_AUTOMATIC:-true}"; then
    run_pass \
      "Nuclei 技术栈自动策略" \
      "$OUT/nuclei.automatic.jsonl" "$OUT/nuclei.automatic.log" \
      "$OUT/urls-priority.txt" "$GENERAL_SEVERITY" \
      -automatic-scan
  fi

  if enabled "${ENABLE_NUCLEI_EXPOSURE:-true}"; then
    run_pass \
      "Nuclei 配置、备份、日志和文件泄露专项" \
      "$OUT/nuclei.exposure.jsonl" "$OUT/nuclei.exposure.log" \
      "$OUT/origins.txt" "$EXTRA_SEVERITY" \
      -tags "${NUCLEI_EXPOSURE_TAGS:-exposure,config,files,backup,token,logs,debug,misconfig}"
  fi

  if enabled "${ENABLE_NUCLEI_API:-true}"; then
    run_pass \
      "Nuclei API、GraphQL、Webhook 和文档专项" \
      "$OUT/nuclei.api.jsonl" "$OUT/nuclei.api.log" \
      "$NUCLEI_EXTRA_TARGETS" "$EXTRA_SEVERITY" \
      -tags "${NUCLEI_API_TAGS:-api,swagger,openapi,graphql,webhook}"
  fi

  if enabled "${ENABLE_NUCLEI_NETWORK:-true}"; then
    run_pass \
      "Nuclei 网络服务与 TLS 专项" \
      "$OUT/nuclei.network.jsonl" "$OUT/nuclei.network.log" \
      "$OUT/open-services.txt" "$EXTRA_SEVERITY" \
      -tags "${NUCLEI_NETWORK_TAGS:-network,ssl}"
  fi

  if enabled "${ENABLE_NUCLEI_DNS:-true}"; then
    run_pass \
      "Nuclei DNS 与接管风险专项" \
      "$OUT/nuclei.dns.jsonl" "$OUT/nuclei.dns.log" \
      "$OUT/domains.all.txt" "$EXTRA_SEVERITY" \
      -tags "${NUCLEI_DNS_TAGS:-dns,takeover}"
  fi
fi

REPORT_ARGS=(
  "$OUT"
  "$OUT/nuclei.official.jsonl"
  "$OUT/nuclei.custom.jsonl"
  "$OUT/nuclei.automatic.jsonl"
  "$OUT/nuclei.exposure.jsonl"
  "$OUT/nuclei.api.jsonl"
  "$OUT/nuclei.network.jsonl"
  "$OUT/nuclei.dns.jsonl"
)
enabled "${NUCLEI_SHOW_FINDINGS:-true}" && REPORT_ARGS+=(--show)
python3 /opt/scanner/nuclei_report.py "${REPORT_ARGS[@]}"
python3 /opt/scanner/summarize.py "$OUT"
log "详细结果：${OUT}/nuclei-findings.md"
