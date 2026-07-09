#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:?result directory required}"
MODE="${2:-standard}"
REAL_RUNNER='/opt/scanner/run-nuclei-v2-real.sh'

[[ -x "$REAL_RUNNER" ]] || {
  echo "[nuclei-closed][ERROR] real runner missing: $REAL_RUNNER" >&2
  exit 30
}

set +e
"$REAL_RUNNER" "$OUT" "$MODE"
REAL_RC=$?
set -e

python3 - "$OUT" "$REAL_RC" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
real_rc = int(sys.argv[2])


def count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.open("r", encoding="utf-8", errors="ignore") if line.strip())
    except OSError:
        return 0


def read_kv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" in raw:
                key, value = raw.split("=", 1)
                values[key.strip()] = value.strip()
    except OSError:
        pass
    return values


def read_errors(path: Path) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return output
    for raw in lines:
        if "\trc=" not in raw:
            continue
        name, value = raw.rsplit("\trc=", 1)
        try:
            rc = int(value)
        except ValueError:
            rc = -1
        output.append({"name": name.strip(), "rc": rc})
    return output

status = read_kv(out / "nuclei-template-status.txt")
template_count = int(status.get("template_count", "0") or 0)
minimum_expected = int(status.get("minimum_expected", "0") or 0)
templates_required_missing = minimum_expected > 0 and template_count < minimum_expected
errors = read_errors(out / "errors.log")
error_names = {str(item.get("name", "")) for item in errors}

passes = {
    "official": (out / "scan-urls.txt", out / "nuclei.official.jsonl", "Nuclei 官方模板全量扫描"),
    "custom": (out / "scan-urls.txt", out / "nuclei.custom.jsonl", "Nuclei 自定义模板扫描"),
    "automatic": (out / "urls-priority.txt", out / "nuclei.automatic.jsonl", "Nuclei 技术栈自动策略"),
    "exposure": (out / "origins.txt", out / "nuclei.exposure.jsonl", "Nuclei 配置、备份、日志和文件泄露专项"),
    "api": (out / "urls-api.txt", out / "nuclei.api.jsonl", "Nuclei API、GraphQL、Webhook 和文档专项"),
    "network": (out / "open-services.txt", out / "nuclei.network.jsonl", "Nuclei 网络服务与 TLS 专项"),
    "dns": (out / "domains.all.txt", out / "nuclei.dns.jsonl", "Nuclei DNS 与接管风险专项"),
}

pass_status: dict[str, dict[str, object]] = {}
for name, (targets, output, display_name) in passes.items():
    target_count = count_lines(targets)
    findings_count = count_lines(output)
    if templates_required_missing and name != "custom":
        state = "failed_templates_missing"
    elif display_name in error_names:
        state = "failed_command"
    elif target_count == 0:
        state = "skipped_no_targets"
    elif findings_count > 0:
        state = "completed_findings"
    else:
        state = "completed_zero_findings"
    pass_status[name] = {
        "status": state,
        "target_count": target_count,
        "findings_count": findings_count,
        "output": output.name,
    }

all_findings = count_lines(out / "nuclei.jsonl")
if templates_required_missing:
    overall = "failed_templates_missing"
    exit_code = 20
elif errors or real_rc != 0:
    overall = "failed_command"
    exit_code = 21 if real_rc == 0 else real_rc
elif all(value["status"] == "skipped_no_targets" for value in pass_status.values()):
    overall = "skipped_no_targets"
    exit_code = 0
elif all_findings > 0:
    overall = "completed_findings"
    exit_code = 0
else:
    overall = "completed_zero_findings"
    exit_code = 0

payload = {
    "engine": "nuclei",
    "status": overall,
    "exit_code": exit_code,
    "real_runner_exit_code": real_rc,
    "template_dir": status.get("template_dir", ""),
    "template_count": template_count,
    "minimum_expected": minimum_expected,
    "templates_required_missing": templates_required_missing,
    "findings_count": all_findings,
    "command_errors": errors,
    "passes": pass_status,
}
(out / "nuclei-status.json").write_text(
    json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(payload, ensure_ascii=False))
raise SystemExit(exit_code)
PY
