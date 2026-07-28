#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:?result directory required}"
MODE="${2:-standard}"
ERROR_LOG="${OUT}/errors.log"
TEMPLATE_DIR="${NUCLEI_TEMPLATE_DIR:-/root/nuclei-templates}"
TEMPLATE_MINIMUM="${NUCLEI_TEMPLATE_MIN_COUNT:-50}"
API_TARGETS="${OUT}/nuclei.api.targets.txt"

log() {
  printf '[nuclei-v2][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

line_count() {
  local path="$1"
  [[ -f "$path" ]] || { echo 0; return; }
  grep -cve '^[[:space:]]*$' "$path" 2>/dev/null || true
}

template_count() {
  [[ -d "$TEMPLATE_DIR" ]] || { echo 0; return; }
  find "$TEMPLATE_DIR" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null |
    wc -l | tr -d ' '
}

write_meta() {
  local name="$1"
  local status="$2"
  local targets="$3"
  local templates="$4"
  local rc="$5"
  python3 - "$OUT/nuclei.${name}.meta.json" "$status" "$targets" "$templates" "$rc" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "status": sys.argv[2],
    "target_count": int(sys.argv[3]),
    "selected_template_count": int(sys.argv[4]),
    "exit_code": int(sys.argv[5]),
}
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
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
  local count
  count="$(template_count)"
  if (( count < TEMPLATE_MINIMUM )); then
    log "模板数量 ${count}，低于 ${TEMPLATE_MINIMUM}，尝试更新到 ${TEMPLATE_DIR}"
    mkdir -p "$TEMPLATE_DIR"
    nuclei -ut -ud "$TEMPLATE_DIR" >"$OUT/nuclei-template-update.log" 2>&1 || true
    count="$(template_count)"
  fi

  {
    echo "enabled=true"
    echo "template_dir=${TEMPLATE_DIR}"
    echo "template_count=${count}"
    echo "minimum_expected=${TEMPLATE_MINIMUM}"
  } >"$OUT/nuclei-template-status.txt"

  if (( count < TEMPLATE_MINIMUM )); then
    log "ERROR: 官方模板不足：${count} < ${TEMPLATE_MINIMUM}"
    printf 'Nuclei 官方模板准备\trc=20\n' >>"$ERROR_LOG"
    return 20
  fi

  : >"$OUT/nuclei.official.templates.txt"
  local list_rc=0
  nuclei -tl -silent -t "$TEMPLATE_DIR" \
    -exclude-tags "${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}" \
    >"$OUT/nuclei.official.templates.txt" 2>"$OUT/nuclei-template-list.log" || list_rc=$?
  if (( list_rc != 0 )); then
    log "ERROR: 无法加载官方模板，rc=${list_rc}"
    printf 'Nuclei 官方模板加载\trc=%s\n' "$list_rc" >>"$ERROR_LOG"
    return "$list_rc"
  fi

  local selected
  selected="$(line_count "$OUT/nuclei.official.templates.txt")"
  if (( selected == 0 )); then
    log "ERROR: 模板目录存在文件，但 Nuclei 没有选中任何模板"
    printf 'Nuclei 官方模板加载\trc=22\n' >>"$ERROR_LOG"
    return 22
  fi
  log "官方模板就绪：文件 ${count}，可加载 ${selected}"
}

selected_templates() {
  local name="$1"
  local severity="$2"
  shift 2
  local list="$OUT/nuclei.${name}.templates.txt"
  : >"$list"
  nuclei -tl -silent \
    -t "$TEMPLATE_DIR" \
    -severity "$severity" \
    -exclude-tags "${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}" \
    "$@" >"$list" 2>"$OUT/nuclei.${name}.template-list.log" || true
  line_count "$list"
}

run_pass() {
  local key="$1"
  local display_name="$2"
  local output="$3"
  local logfile="$4"
  local targets="$5"
  local severity="$6"
  local source="$7"
  local selected="$8"
  shift 8

  : >"$output"
  : >"$logfile"

  local target_count
  target_count="$(line_count "$targets")"
  if (( target_count == 0 )); then
    write_meta "$key" "skipped_no_targets" 0 "$selected" 0
    return 0
  fi
  if (( selected == 0 )); then
    log "WARN: ${display_name} 有 ${target_count} 个目标，但未选中模板"
    printf '%s\trc=22\n' "$display_name" >>"$ERROR_LOG"
    write_meta "$key" "failed_no_templates_selected" "$target_count" 0 22
    return 0
  fi

  local args=(
    -l "$targets"
    -silent -jsonl
    -t "$source"
    -severity "$severity"
    -exclude-tags "${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}"
    -rate-limit "${NUCLEI_RATE_LIMIT:-120}"
    -concurrency "${NUCLEI_EXTRA_CONCURRENCY:-20}"
    -bulk-size "${NUCLEI_BULK_SIZE:-20}"
    -timeout "${NUCLEI_TIMEOUT:-10}"
    -retries "${NUCLEI_RETRIES:-1}"
    -duc
    -o "$output"
  )
  local help
  help="$(nuclei -h 2>&1 || true)"
  grep -q -- '-stats' <<<"$help" && args+=(-stats)
  grep -q -- '-stats-json' <<<"$help" && args+=(-stats-json)
  grep -q -- '-stats-interval' <<<"$help" && args+=(-stats-interval 30)

  log "开始：${display_name}（目标 ${target_count}，模板 ${selected}）"
  if nuclei "${args[@]}" "$@" 2> >(tee "$logfile" >&2); then
    write_meta "$key" "completed" "$target_count" "$selected" 0
    log "完成：${display_name}，命中 $(line_count "$output")"
  else
    local rc=$?
    log "WARN: ${display_name} 失败 rc=${rc}"
    printf '%s\trc=%s\n' "$display_name" "$rc" >>"$ERROR_LOG"
    write_meta "$key" "failed_command" "$target_count" "$selected" "$rc"
  fi
}

mkdir -p "$OUT"
touch "$ERROR_LOG"
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
  "$OUT/content-endpoints.txt" 2>/dev/null |
  sed '/^[[:space:]]*$/d' | awk '!seen[$0]++' >"$API_TARGETS"

POLICY="$(resolve_policy)"
GENERAL_SEVERITY="$(resolve_severity)"
EXTRA_SEVERITY="${NUCLEI_EXTRA_SEVERITY:-info,low,medium,high,critical}"

{
  echo "nuclei_v2=true"
  echo "nuclei_policy=${POLICY}"
  echo "nuclei_template_dir=${TEMPLATE_DIR}"
  echo "nuclei_general_severity=${GENERAL_SEVERITY}"
  echo "nuclei_extra_severity=${EXTRA_SEVERITY}"
  echo "nuclei_exclude_tags=${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}"
} >>"$OUT/manifest.txt"

for name in official custom automatic exposure api network dns; do
  : >"$OUT/nuclei.${name}.jsonl"
  : >"$OUT/nuclei.${name}.log"
  : >"$OUT/nuclei.${name}.templates.txt"
  write_meta "$name" "not_scheduled" 0 0 0
done

OFFICIAL_SELECTED="$(selected_templates official "$GENERAL_SEVERITY")"
run_pass \
  official "Nuclei 官方模板全量扫描" \
  "$OUT/nuclei.official.jsonl" "$OUT/nuclei.official.log" \
  "$OUT/scan-urls.txt" "$GENERAL_SEVERITY" "$TEMPLATE_DIR" "$OFFICIAL_SELECTED"

if find /opt/pocs/nuclei -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .; then
  CUSTOM_SELECTED="$(find /opt/pocs/nuclei -type f \( -name '*.yaml' -o -name '*.yml' \) | wc -l | tr -d ' ')"
  find /opt/pocs/nuclei -type f \( -name '*.yaml' -o -name '*.yml' \) | sort >"$OUT/nuclei.custom.templates.txt"
  run_pass \
    custom "Nuclei 自定义模板扫描" \
    "$OUT/nuclei.custom.jsonl" "$OUT/nuclei.custom.log" \
    "$OUT/scan-urls.txt" "$GENERAL_SEVERITY" /opt/pocs/nuclei "$CUSTOM_SELECTED"
else
  write_meta custom "skipped_no_templates" "$(line_count "$OUT/scan-urls.txt")" 0 0
fi

if [[ "$POLICY" != "off" ]]; then
  if [[ "$POLICY" == "balanced" || "$POLICY" == "deep" ]] && enabled "${ENABLE_NUCLEI_AUTOMATIC:-true}"; then
    cp "$OUT/nuclei.official.templates.txt" "$OUT/nuclei.automatic.templates.txt"
    run_pass \
      automatic "Nuclei 技术栈自动策略" \
      "$OUT/nuclei.automatic.jsonl" "$OUT/nuclei.automatic.log" \
      "$OUT/urls-priority.txt" "$GENERAL_SEVERITY" "$TEMPLATE_DIR" "$OFFICIAL_SELECTED" \
      -automatic-scan
  else
    write_meta automatic "disabled_policy" "$(line_count "$OUT/urls-priority.txt")" 0 0
  fi

  if enabled "${ENABLE_NUCLEI_EXPOSURE:-true}"; then
    EXPOSURE_TAGS="${NUCLEI_EXPOSURE_TAGS:-exposure,config,files,backup,token,logs,debug,misconfig}"
    EXPOSURE_SELECTED="$(selected_templates exposure "$EXTRA_SEVERITY" -tags "$EXPOSURE_TAGS")"
    run_pass \
      exposure "Nuclei 配置、备份、日志和文件泄露专项" \
      "$OUT/nuclei.exposure.jsonl" "$OUT/nuclei.exposure.log" \
      "$OUT/origins.txt" "$EXTRA_SEVERITY" "$TEMPLATE_DIR" "$EXPOSURE_SELECTED" \
      -tags "$EXPOSURE_TAGS"
  else
    write_meta exposure "disabled_policy" "$(line_count "$OUT/origins.txt")" 0 0
  fi

  if enabled "${ENABLE_NUCLEI_API:-true}"; then
    API_TAGS="${NUCLEI_API_TAGS:-api,swagger,openapi,graphql,webhook}"
    API_SELECTED="$(selected_templates api "$EXTRA_SEVERITY" -tags "$API_TAGS")"
    run_pass \
      api "Nuclei API、GraphQL、Webhook 和文档专项" \
      "$OUT/nuclei.api.jsonl" "$OUT/nuclei.api.log" \
      "$API_TARGETS" "$EXTRA_SEVERITY" "$TEMPLATE_DIR" "$API_SELECTED" \
      -tags "$API_TAGS"
  else
    write_meta api "disabled_policy" "$(line_count "$API_TARGETS")" 0 0
  fi

  if enabled "${ENABLE_NUCLEI_NETWORK:-true}"; then
    NETWORK_TAGS="${NUCLEI_NETWORK_TAGS:-network,ssl}"
    NETWORK_SELECTED="$(selected_templates network "$EXTRA_SEVERITY" -tags "$NETWORK_TAGS")"
    run_pass \
      network "Nuclei 网络服务与 TLS 专项" \
      "$OUT/nuclei.network.jsonl" "$OUT/nuclei.network.log" \
      "$OUT/open-services.txt" "$EXTRA_SEVERITY" "$TEMPLATE_DIR" "$NETWORK_SELECTED" \
      -tags "$NETWORK_TAGS"
  else
    write_meta network "disabled_policy" "$(line_count "$OUT/open-services.txt")" 0 0
  fi

  if enabled "${ENABLE_NUCLEI_DNS:-true}"; then
    DNS_TAGS="${NUCLEI_DNS_TAGS:-dns,takeover}"
    DNS_SELECTED="$(selected_templates dns "$EXTRA_SEVERITY" -tags "$DNS_TAGS")"
    run_pass \
      dns "Nuclei DNS 与接管风险专项" \
      "$OUT/nuclei.dns.jsonl" "$OUT/nuclei.dns.log" \
      "$OUT/domains.all.txt" "$EXTRA_SEVERITY" "$TEMPLATE_DIR" "$DNS_SELECTED" \
      -tags "$DNS_TAGS"
  else
    write_meta dns "disabled_policy" "$(line_count "$OUT/domains.all.txt")" 0 0
  fi
else
  for name in automatic exposure api network dns; do
    write_meta "$name" "disabled_policy" 0 0 0
  done
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
