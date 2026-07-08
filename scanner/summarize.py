#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.open(encoding="utf-8", errors="ignore") if line.strip())


def load_json(path: Path, default: Any) -> Any:
    if not path.is_file() or path.stat().st_size == 0:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return default


def nuclei_severities(path: Path) -> Counter[str]:
    values: Counter[str] = Counter()
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        severity = str((item.get("info") or {}).get("severity") or "unknown").lower()
        values[severity] += 1
    return values


def afrog_severities(path: Path) -> Counter[str]:
    values: Counter[str] = Counter()
    data = load_json(path, [])
    if isinstance(data, dict):
        data = data.get("results") or data.get("data") or []
    if not isinstance(data, list):
        return values
    for item in data:
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        severity = str(info.get("severity") or item.get("severity") or "unknown").lower()
        values[severity] += 1
    return values


def ffuf_summary(directory: Path) -> tuple[int, Counter[int]]:
    total = 0
    statuses: Counter[int] = Counter()
    if not directory.is_dir():
        return total, statuses
    for path in directory.glob("*.json"):
        data = load_json(path, {})
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            continue
        total += len(results)
        for item in results:
            if isinstance(item, dict):
                try:
                    statuses[int(item.get("status"))] += 1
                except (TypeError, ValueError):
                    pass
    return total, statuses


def ordered(counter: Counter[Any]) -> dict[str, int]:
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    result: dict[str, int] = {}
    for key in order:
        if counter.get(key):
            result[key] = counter[key]
    for key, value in sorted(counter.items(), key=lambda item: str(item[0])):
        string_key = str(key)
        if string_key not in result and value:
            result[string_key] = value
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize.py <result_dir>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    target_counts = load_json(root / "target-counts.json", {})
    nuclei = nuclei_severities(root / "nuclei.jsonl")
    afrog = afrog_severities(root / "afrog.json")
    ffuf_total, ffuf_statuses = ffuf_summary(root / "ffuf")

    errors = []
    error_path = root / "errors.log"
    if error_path.is_file():
        errors = [
            line.strip()
            for line in error_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        ]

    summary = {
        "targets": target_counts,
        "subdomains_discovered": line_count(root / "subfinder.txt"),
        "resolved_domains": line_count(root / "dnsx.jsonl"),
        "open_services": line_count(root / "open-services.txt"),
        "live_urls": line_count(root / "live-urls.txt"),
        "crawled_urls": line_count(root / "katana.txt"),
        "sourcemaps": line_count(root / "sourcemaps.jsonl"),
        "total_scan_urls": line_count(root / "scan-urls.txt"),
        "nuclei_findings": ordered(nuclei),
        "afrog_findings": ordered(afrog),
        "ffuf_findings": ffuf_total,
        "ffuf_statuses": {str(k): v for k, v in sorted(ffuf_statuses.items())},
        "stage_errors": errors,
    }

    (root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# 扫描结果汇总",
        "",
        f"- 规范化目标：{target_counts.get('normalized', 0)}",
        f"- 被动发现子域名：{summary['subdomains_discovered']}",
        f"- DNS 有效记录：{summary['resolved_domains']}",
        f"- 开放服务：{summary['open_services']}",
        f"- 存活 URL：{summary['live_urls']}",
        f"- 爬取 URL：{summary['crawled_urls']}",
        f"- Sourcemap 泄露：{summary['sourcemaps']}",
        f"- 最终漏洞扫描 URL：{summary['total_scan_urls']}",
        "",
        "## Nuclei",
        "",
    ]
    if summary["nuclei_findings"]:
        lines.extend(f"- {key}: {value}" for key, value in summary["nuclei_findings"].items())
    else:
        lines.append("- 未发现结果或该阶段未成功运行")

    lines.extend(["", "## afrog", ""])
    if summary["afrog_findings"]:
        lines.extend(f"- {key}: {value}" for key, value in summary["afrog_findings"].items())
    else:
        lines.append("- 未发现结果或该阶段未成功运行")

    lines.extend(
        [
            "",
            "## 高价值暴露",
            "",
            f"- Sourcemap 命中：{summary['sourcemaps']}",
            f"- ffuf 命中：{summary['ffuf_findings']}",
        ]
    )
    if summary["ffuf_statuses"]:
        lines.extend(f"- HTTP {key}: {value}" for key, value in summary["ffuf_statuses"].items())

    lines.extend(["", "## 阶段错误", ""])
    if errors:
        lines.extend(f"- {item}" for item in errors)
    else:
        lines.append("- 无")

    (root / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
