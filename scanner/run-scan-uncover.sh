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
UNCOVER_FAILED=false

log() {
  printf '[scanner-uncover][%s] %s\n' "$(date '+%F %T')" "$*"
}

enabled() {
  [[ "${1,,}" == "true" || "$1" == "1" || "${1,,}" == "yes" || "${1,,}" == "on" ]]
}

cleanup() {
  rm -f "$AUGMENTED_TARGETS"
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
    hunterhow google onyphe driftnet daydaymap nerdydata; do
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
  if [[ "$MODE" == "deep" ]]; then
    expanded="true"
  fi
  if [[ -n "${UNCOVER_EXPANDED_QUERIES_OVERRIDE:-}" ]]; then
    expanded="${UNCOVER_EXPANDED_QUERIES_OVERRIDE}"
  fi

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

run_uncover

cat \
  "$TARGET_FILE" \
  "$OUT/uncover-hosts.txt" \
  "$OUT/uncover-services.txt" \
  "$OUT/uncover-urls.txt" 2>/dev/null | \
  sed '/^[[:space:]]*$/d' | sort -u >"$AUGMENTED_TARGETS"

/opt/scanner/run-scan.sh "$AUGMENTED_TARGETS" "$MODE"

if [[ "$UNCOVER_FAILED" == "true" ]]; then
  printf 'Uncover 多引擎资产聚合\trc=partial-or-failed\n' >>"$OUT/errors.log"
  python3 /opt/scanner/summarize.py "$OUT"
fi
