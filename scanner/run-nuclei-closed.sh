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


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


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
        if name.strip().startswith("Nuclei"):
            output.append({"name": name.strip(), "rc": rc})
    return output


status = read_kv(out / "nuclei-template-status.txt")
template_count = int(status.get("template_count", "0") or 0)
minimum_expected = int(status.get("minimum_expected", "0") or 0)
templates_required_missing = minimum_expected > 0 and template_count < minimum_expected

passes = {
    "official": "nuclei.official.jsonl",
    "custom": "nuclei.custom.jsonl",
    "automatic": "nuclei.automatic.jsonl",
    "exposure": "nuclei.exposure.jsonl",
    "api": "nuclei.api.jsonl",
    "network": "nuclei.network.jsonl",
    "dns": "nuclei.dns.jsonl",
}

pass_status: dict[str, dict[str, object]] = {}
for name, output_name in passes.items():
    meta = read_json(out / f"nuclei.{name}.meta.json")
    findings_count = count_lines(out / output_name)
    selected_count = int(meta.get("selected_template_count", count_lines(out / f"nuclei.{name}.templates.txt")) or 0)
    target_count = int(meta.get("target_count", 0) or 0)
    state = str(meta.get("status") or "unknown")
    if state == "completed":
        state = "completed_findings" if findings_count > 0 else "completed_zero_findings"
    pass_status[name] = {
        "status": state,
        "target_count": target_count,
        "selected_template_count": selected_count,
        "findings_count": findings_count,
        "exit_code": int(meta.get("exit_code", 0) or 0),
        "output": output_name,
        "log": f"nuclei.{name}.log",
        "meta": f"nuclei.{name}.meta.json",
    }

errors = read_errors(out / "errors.log")
all_findings = count_lines(out / "nuclei.jsonl")
states = {str(value.get("status") or "") for value in pass_status.values()}

if templates_required_missing:
    overall = "failed_templates_missing"
    exit_code = 20
elif "failed_no_templates_selected" in states:
    overall = "failed_no_templates_selected"
    exit_code = 22
elif "failed_command" in states or errors or real_rc != 0:
    overall = "failed_command"
    exit_code = real_rc if real_rc != 0 else 21
elif all_findings > 0:
    overall = "completed_findings"
    exit_code = 0
elif all(
    state.startswith("skipped_") or state in {"disabled_policy", "not_scheduled"}
    for state in states
):
    overall = "skipped_no_targets"
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
