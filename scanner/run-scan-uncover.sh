#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_FILE="${1:-${TARGET_FILE:-/work/input/targets.txt}}"
MODE="${2:-${SCAN_MODE:-standard}}"
SCAN_ID_RAW="${SCAN_ID:-$(date +%Y%m%d-%H%M%S)}"
SCAN_ID="$(printf '%s' "$SCAN_ID_RAW" | tr -cd 'a-zA-Z0-9._-' | cut -c1-80)"
[[ -n "$SCAN_ID" ]] || SCAN_ID="$(date +%Y%m%d-%H%M%S)"
export SCAN_ID

OUT="/work/results/${SCAN_ID}"
PROVIDER_CONFIG="${UNCOVER_PROVIDER_CONFIG:-/run/secrets/uncover-provider.yaml}"
AUGMENTED_TARGETS="/tmp/arl-uncover-targets-${SCAN_ID}.txt"
NUCLEI_EXTRA_TARGETS="/tmp/arl-nuclei-extra-${SCAN_ID}.txt"
UNCOVER_FAILED=false
NUCLEI_REQUESTED="${ENABLE_NUCLEI:-true}"

log() {
  printf '[scanner-plus][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

cleanup() {
  rm -f "$AUGMENTED_TARGETS" "$NUCLEI_EXTRA_TARGETS"
}
trap cleanup EXIT

mkdir -p "$OUT"
cp "$TARGET_FILE" "$OUT/targets.original.txt"
python3 /opt/scanner/prepare_targets.py "$TARGET_FILE" "$OUT"

: >"$OUT/uncover.jsonl"
: >"$OUT/uncover-hosts.txt"
: >"$OUT/uncover-services.txt"
: >"$OUT/uncover-urls.txt"
: >"$OUT/uncover-ip-candidates.txt"
: >"$OUT/uncover.scoped.jsonl"
: >"$OUT/uncover.candidates.jsonl"
printf '{"status":"disabled"}\n' >"$OUT/uncover-stats.json"

resolve_engines() {
  local requested="${UNCOVER_ENGINES:-auto}"
  if [[ "$requested" != "auto" && -n "$requested" ]]; then
    printf '%s' "$requested"
    return 0
  fi

  [[ -f "$PROVIDER_CONFIG" ]] || return 0
  local engine
  local found=()
  for engine in \
    shodan censys fofa quake hunter zoomeye netlas criminalip publicwww \
    hunterhow google onyphe driftnet daydaymap; do
    if grep -Eq "^[[:space:]]*${engine}:[[:space:]]*$" "$PROVIDER_CONFIG"; then
      found+=("$engine")
    fi
  done
  local joined=""
  if ((${#found[@]} > 0)); then
    joined="$(IFS=,; echo "${found[*]}")"
  fi
  printf '%s' "$joined"
}

run_uncover() {
  if ! enabled "${ENABLE_UNCOVER:-true}"; then
    log "Uncover 已关闭，继续原扫描链"
    return 0
  fi
  if [[ ! -s "$OUT/domains.txt" ]]; then
    log "目标中没有域名，跳过 Uncover"
    printf '{"status":"skipped-no-domain"}\n' >"$OUT/uncover-stats.json"
    return 0
  fi
  if [[ ! -f "$PROVIDER_CONFIG" ]]; then
    log "未发现 ${PROVIDER_CONFIG}，跳过 Uncover；原扫描链不受影响"
    printf '{"status":"skipped-no-config"}\n' >"$OUT/uncover-stats.json"
    return 0
  fi

  local expanded="false"
  [[ "$MODE" == "deep" ]] && expanded="true"
  [[ -n "${UNCOVER_EXPANDED_QUERIES_OVERRIDE:-}" ]] && expanded="${UNCOVER_EXPANDED_QUERIES_OVERRIDE}"

  local prepare_args=(prepare "$OUT/domains.txt" "$OUT/uncover-queries.txt")
  enabled "$expanded" && prepare_args+=(--expanded)
  python3 /opt/scanner/uncover_assets.py "${prepare_args[@]}"

  local engines
  engines="$(resolve_engines)"
  if [[ -z "$engines" ]]; then
    log "Uncover 配置中没有识别到可用引擎，跳过"
    printf '{"status":"skipped-no-engine"}\n' >"$OUT/uncover-stats.json"
    return 0
  fi

  log "开始多引擎资产聚合：${engines}"
  if ! uncover \
    -q "$OUT/uncover-queries.txt" \
    -e "$engines" \
    -pc "$PROVIDER_CONFIG" \
    -json \
    -limit "${UNCOVER_LIMIT:-100}" \
    -rate-limit "${UNCOVER_RATE_LIMIT:-2}" \
    -retry 1 \
    -timeout 30 \
    -o "$OUT/uncover.jsonl"; then
    UNCOVER_FAILED=true
    log "Uncover 返回失败；继续原扫描链"
  fi

  local merge_args=(merge "$OUT/uncover.jsonl" "$OUT/domains.txt" "$OUT")
  enabled "${UNCOVER_ACCEPT_IP_ONLY:-false}" && merge_args+=(--accept-ip-only)
  python3 /opt/scanner/uncover_assets.py "${merge_args[@]}"

  local hosts services urls candidates
  hosts="$(grep -cve '^[[:space:]]*$' "$OUT/uncover-hosts.txt" 2>/dev/null || true)"
  services="$(grep -cve '^[[:space:]]*$' "$OUT/uncover-services.txt" 2>/dev/null || true)"
  urls="$(grep -cve '^[[:space:]]*$' "$OUT/uncover-urls.txt" 2>/dev/null || true)"
  candidates="$(grep -cve '^[[:space:]]*$' "$OUT/uncover-ip-candidates.txt" 2>/dev/null || true)"
  log "Uncover 完成：域名 ${hosts}，服务 ${services}，URL ${urls}，IP 候选 ${candidates}"
}

ensure_nuclei_templates() {
  local template_dir="${NUCLEI_TEMPLATE_DIR:-/root/nuclei-templates}"
  local minimum="${NUCLEI_TEMPLATE_MIN_COUNT:-50}"
  local count=0

  if ! enabled "$NUCLEI_REQUESTED"; then
    {
      echo "enabled=false"
      echo "template_dir=${template_dir}"
      echo "template_count=0"
      echo "minimum_expected=${minimum}"
    } >"$OUT/nuclei-template-status.txt"
    return 0
  fi

  if [[ -d "$template_dir" ]]; then
    count="$(find "$template_dir" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l | tr -d ' ')"
  fi
  if (( count < minimum )); then
    log "Nuclei 模板数量 ${count}，低于 ${minimum}，尝试更新模板"
    nuclei -ut >"$OUT/nuclei-template-update.log" 2>&1 || true
    count="$(find "$template_dir" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l | tr -d ' ')"
  fi
  {
    echo "enabled=true"
    echo "template_dir=${template_dir}"
    echo "template_count=${count}"
    echo "minimum_expected=${minimum}"
  } >"$OUT/nuclei-template-status.txt"
  if (( count == 0 )); then
    log "WARN: Nuclei 官方模板仍为空；扫描会继续，但官方模板不会产生结果"
  fi
}

resolve_nuclei_policy() {
  local policy="${NUCLEI_POLICY:-auto}"
  if [[ "$policy" == "auto" ]]; then
    case "$MODE" in
      fast) policy="safe" ;;
      standard) policy="balanced" ;;
      deep) policy="deep" ;;
    esac
  fi
  case "$policy" in
    off|safe|balanced|exposure|deep) ;;
    *)
      log "WARN: 未知 NUCLEI_POLICY=${policy}，回退 balanced"
      policy="balanced"
      ;;
  esac
  printf '%s' "$policy"
}

resolve_general_nuclei_severity() {
  if [[ -n "${NUCLEI_SEVERITY_OVERRIDE:-}" ]]; then
    printf '%s' "$NUCLEI_SEVERITY_OVERRIDE"
    return 0
  fi
  case "$MODE" in
    fast) printf 'high,critical' ;;
    standard) printf 'medium,high,critical' ;;
    deep) printf 'low,medium,high,critical' ;;
  esac
}

run_nuclei_pass() {
  local name="$1"
  local output="$2"
  local logfile="$3"
  local targets="$4"
  shift 4

  : >"$output"
  : >"$logfile"
  [[ -s "$targets" ]] || return 0

  log "开始：${name}"
  if nuclei \
    -l "$targets" \
    -silent -jsonl \
    -severity "${NUCLEI_PASS_SEVERITY:-info,low,medium,high,critical}" \
    -exclude-tags "${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}" \
    -rate-limit "${NUCLEI_RATE_LIMIT:-120}" \
    -concurrency "${NUCLEI_EXTRA_CONCURRENCY:-20}" \
    -bulk-size 20 \
    -timeout 10 -retries 1 -duc \
    -o "$output" \
    "$@" 2> >(tee "$logfile" >&2); then
    log "完成：${name}"
  else
    local rc=$?
    log "WARN: ${name} 失败，退出码 ${rc}；保留日志并继续"
    printf '%s\trc=%s\n' "$name" "$rc" >>"$OUT/errors.log"
  fi
}

run_nuclei_enhancements() {
  if ! enabled "$NUCLEI_REQUESTED"; then
    return 0
  fi

  python3 /opt/scanner/extract_api_surface.py \
    "$OUT" "$OUT/live-urls.txt" "$OUT/katana.txt" "$OUT/sourcemap-candidates.txt"

  cat \
    "$OUT/live-urls.txt" \
    "$OUT/api-endpoints.txt" \
    "$OUT/api-docs-endpoints.txt" \
    "$OUT/webhook-endpoints.txt" 2>/dev/null | \
    sed '/^[[:space:]]*$/d' | sort -u >"$NUCLEI_EXTRA_TARGETS"

  local policy general_severity
  policy="$(resolve_nuclei_policy)"
  general_severity="$(resolve_general_nuclei_severity)"
  echo "nuclei_policy=${policy}" >>"$OUT/manifest.txt"
  echo "nuclei_general_severity=${general_severity}" >>"$OUT/manifest.txt"
  echo "nuclei_exclude_tags=${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive,bruteforce}" >>"$OUT/manifest.txt"

  : >"$OUT/nuclei.official.jsonl"
  : >"$OUT/nuclei.custom.jsonl"
  : >"$OUT/nuclei.automatic.jsonl"
  : >"$OUT/nuclei.exposure.jsonl"
  : >"$OUT/nuclei.api.jsonl"

  NUCLEI_PASS_SEVERITY="$general_severity" run_nuclei_pass \
    "Nuclei 官方模板扫描" \
    "$OUT/nuclei.official.jsonl" \
    "$OUT/nuclei.official.log" \
    "$OUT/scan-urls.txt"

  if find /opt/pocs/nuclei -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .; then
    NUCLEI_PASS_SEVERITY="$general_severity" run_nuclei_pass \
      "Nuclei 自定义模板扫描" \
      "$OUT/nuclei.custom.jsonl" \
      "$OUT/nuclei.custom.log" \
      "$OUT/scan-urls.txt" \
      -t /opt/pocs/nuclei
  fi

  if [[ "$policy" != "off" ]]; then
    if [[ "$policy" == "balanced" || "$policy" == "deep" ]] && enabled "${ENABLE_NUCLEI_AUTOMATIC:-true}"; then
      NUCLEI_PASS_SEVERITY="$general_severity" run_nuclei_pass \
        "Nuclei 技术栈自动策略扫描" \
        "$OUT/nuclei.automatic.jsonl" \
        "$OUT/nuclei.automatic.log" \
        "$OUT/live-urls.txt" \
        -automatic-scan
    fi

    if enabled "${ENABLE_NUCLEI_EXPOSURE:-true}"; then
      NUCLEI_PASS_SEVERITY="${NUCLEI_EXTRA_SEVERITY:-info,low,medium,high,critical}" run_nuclei_pass \
        "Nuclei 文件泄露与错误配置专项" \
        "$OUT/nuclei.exposure.jsonl" \
        "$OUT/nuclei.exposure.log" \
        "$OUT/live-urls.txt" \
        -tags "${NUCLEI_EXPOSURE_TAGS:-exposure,config,files,backup,token,logs,debug,misconfig}"
    fi

    if enabled "${ENABLE_NUCLEI_API:-true}" && [[ -s "$NUCLEI_EXTRA_TARGETS" ]]; then
      NUCLEI_PASS_SEVERITY="${NUCLEI_EXTRA_SEVERITY:-info,low,medium,high,critical}" run_nuclei_pass \
        "Nuclei API/HTTP/Webhook 调用面专项" \
        "$OUT/nuclei.api.jsonl" \
        "$OUT/nuclei.api.log" \
        "$NUCLEI_EXTRA_TARGETS" \
        -tags "${NUCLEI_API_TAGS:-api,swagger,openapi,graphql,webhook}"
    fi
  fi

  local report_args=(
    "$OUT"
    "$OUT/nuclei.official.jsonl"
    "$OUT/nuclei.custom.jsonl"
    "$OUT/nuclei.automatic.jsonl"
    "$OUT/nuclei.exposure.jsonl"
    "$OUT/nuclei.api.jsonl"
  )
  enabled "${NUCLEI_SHOW_FINDINGS:-true}" && report_args+=(--show)
  python3 /opt/scanner/nuclei_report.py "${report_args[@]}"
  python3 /opt/scanner/summarize.py "$OUT"
}

run_uncover
ensure_nuclei_templates

cat \
  "$TARGET_FILE" \
  "$OUT/uncover-hosts.txt" \
  "$OUT/uncover-services.txt" \
  "$OUT/uncover-urls.txt" 2>/dev/null | \
  sed '/^[[:space:]]*$/d' | sort -u >"$AUGMENTED_TARGETS"

if enabled "$NUCLEI_REQUESTED"; then
  export ENABLE_NUCLEI=false
fi
/opt/scanner/run-scan.sh "$AUGMENTED_TARGETS" "$MODE"
export ENABLE_NUCLEI="$NUCLEI_REQUESTED"
run_nuclei_enhancements

{
  printf 'uncover='
  uncover -version 2>&1 | head -n 1 || true
} >>"$OUT/manifest.txt"

if [[ "$UNCOVER_FAILED" == "true" ]]; then
  printf 'Uncover 多引擎资产聚合\trc=partial-or-failed\n' >>"$OUT/errors.log"
  python3 /opt/scanner/summarize.py "$OUT"
fi

log "Nuclei 详细结果：${OUT}/nuclei-findings.md"
