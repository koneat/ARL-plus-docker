#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_FILE="${1:-}"
MODE="${2:-standard}"

usage() {
  cat <<'EOF'
用法：
  bash scripts/scan-enhanced.sh <目标文件> [fast|standard|deep]

目标文件每行支持：
  example.com
  https://example.com/path
  192.0.2.10
  192.0.2.0/24
  example.com:8443

扫描模式：
  fast      快速验证，关闭 AlterX 与二次爬取
  standard  默认，启用历史 URL、TLS SAN、智能排序和内容验证
  deep      深度，扩大排列、历史 URL、二次爬取和内容验证上限

示例：
  bash scripts/scan-enhanced.sh targets.txt standard
EOF
}

if [[ -z "$TARGET_FILE" || "$TARGET_FILE" == "-h" || "$TARGET_FILE" == "--help" ]]; then
  usage
  [[ -n "$TARGET_FILE" ]] && exit 0
  exit 2
fi

case "$MODE" in
  fast|standard|deep) ;;
  *)
    echo "不支持的扫描模式：$MODE" >&2
    usage >&2
    exit 2
    ;;
esac

command -v docker >/dev/null 2>&1 || {
  echo "未找到 docker" >&2
  exit 1
}
docker compose version >/dev/null 2>&1 || {
  echo "需要 Docker Compose v2（docker compose）" >&2
  exit 1
}

TARGET_ABS="$(realpath -e "$TARGET_FILE" 2>/dev/null || true)"
[[ -n "$TARGET_ABS" && -f "$TARGET_ABS" ]] || {
  echo "目标文件不存在：$TARGET_FILE" >&2
  exit 1
}

mkdir -p \
  scan-results \
  scanner-cache/config \
  scanner-cache/nuclei-templates \
  scanner-pocs/nuclei \
  scanner-pocs/afrog \
  scanner-secrets
chmod 700 scanner-secrets 2>/dev/null || true

COMPOSE=(
  docker compose
  --project-name arl-plus-scanner
  -f docker-compose.scanner.yml
  --profile scanner
)

if [[ "${SCANNER_SKIP_BUILD:-false}" != "true" ]]; then
  "${COMPOSE[@]}" build scanner
fi

"${COMPOSE[@]}" run --rm \
  --volume "$TARGET_ABS:/work/input/targets.txt:ro" \
  scanner \
  /opt/scanner/run-scan-v2.sh /work/input/targets.txt "$MODE"

if [[ -L scan-results/latest ]]; then
  latest="$(readlink scan-results/latest)"
  echo "结果目录：$ROOT_DIR/scan-results/$latest"
  echo "Markdown 汇总：$ROOT_DIR/scan-results/$latest/summary.md"
  echo "HTML 总报告：$ROOT_DIR/scan-results/$latest/report.html"
  echo "Nuclei 详情：$ROOT_DIR/scan-results/$latest/nuclei-findings.md"
  echo "内容审计：$ROOT_DIR/scan-results/$latest/content-findings.md"
else
  echo "扫描完成，请查看：$ROOT_DIR/scan-results/" >&2
fi
