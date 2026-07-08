#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value if item is not None)
    return str(value)


def parse_limit() -> int:
    raw = os.getenv("NUCLEI_REPORT_LIMIT", "100").strip()
    try:
        value = int(raw)
    except ValueError:
        return 100
    return max(1, min(value, 1000))


def get_template_id(item: dict[str, Any]) -> str:
    return text(
        item.get("template-id")
        or item.get("templateID")
        or item.get("template_id")
        or item.get("template")
        or "unknown-template"
    )


def get_matched_at(item: dict[str, Any]) -> str:
    return text(
        item.get("matched-at")
        or item.get("matched")
        or item.get("url")
        or item.get("host")
        or item.get("ip")
        or ""
    )


def normalize(item: dict[str, Any], source_file: str) -> dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    severity = text(info.get("severity") or item.get("severity") or "unknown").lower()
    if severity not in SEVERITY_ORDER:
        severity = "unknown"

    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    extracted = item.get("extracted-results") or item.get("extracted_results") or []
    if not isinstance(extracted, list):
        extracted = [extracted]

    return {
        **item,
        "_source_file": source_file,
        "_normalized": {
            "template_id": get_template_id(item),
            "name": text(info.get("name") or item.get("name") or ""),
            "severity": severity,
            "matched_at": get_matched_at(item),
            "host": text(item.get("host") or item.get("ip") or ""),
            "type": text(item.get("type") or item.get("protocol") or ""),
            "matcher_name": text(item.get("matcher-name") or item.get("matcher_name") or ""),
            "extracted_results": [text(value) for value in extracted if text(value)],
            "cve_id": text(classification.get("cve-id") or classification.get("cve_id") or ""),
            "cwe_id": text(classification.get("cwe-id") or classification.get("cwe_id") or ""),
            "tags": text(info.get("tags") or ""),
            "timestamp": text(item.get("timestamp") or ""),
        },
    }


def dedupe_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    normalized = item["_normalized"]
    return (
        normalized["template_id"],
        normalized["matched_at"] or normalized["host"],
        normalized["matcher_name"],
        "|".join(normalized["extracted_results"]),
    )


def load_findings(paths: list[Path]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    invalid = 0
    duplicates = 0
    per_file: dict[str, dict[str, int]] = {}

    for path in paths:
        file_stats = {"lines": 0, "valid": 0, "invalid": 0, "duplicates": 0}
        per_file[path.name] = file_stats
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw.strip():
                continue
            file_stats["lines"] += 1
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                invalid += 1
                file_stats["invalid"] += 1
                continue
            if not isinstance(item, dict):
                invalid += 1
                file_stats["invalid"] += 1
                continue
            normalized = normalize(item, path.name)
            key = dedupe_key(normalized)
            if key in seen:
                duplicates += 1
                file_stats["duplicates"] += 1
                continue
            seen.add(key)
            findings.append(normalized)
            file_stats["valid"] += 1

    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["_normalized"]["severity"], 99),
            item["_normalized"]["template_id"],
            item["_normalized"]["matched_at"],
        )
    )
    return findings, {
        "invalid_lines": invalid,
        "duplicates_removed": duplicates,
        "files": per_file,
    }


def markdown(findings: list[dict[str, Any]], limit: int) -> str:
    lines = [
        "# Nuclei 详细结果",
        "",
        f"- 去重后结果：{len(findings)}",
        f"- 当前报告最多展示：{limit}",
        "",
    ]
    if not findings:
        lines.extend(
            [
                "未发现结果。请同时检查：",
                "",
                "- `nuclei-status.json`",
                "- `nuclei.*.log`",
                "- `nuclei-template-status.txt`",
                "- `scan-urls.txt` 是否为空",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "| 严重级别 | 模板 | 名称 | 命中位置 | 来源 |",
            "|---|---|---|---|---|",
        ]
    )
    for item in findings[:limit]:
        value = item["_normalized"]
        def escape(raw: str) -> str:
            return raw.replace("|", "\\|").replace("\n", " ")

        lines.append(
            "| {severity} | `{template}` | {name} | `{matched}` | `{source}` |".format(
                severity=escape(value["severity"]),
                template=escape(value["template_id"]),
                name=escape(value["name"] or "-"),
                matched=escape(value["matched_at"] or value["host"] or "-"),
                source=escape(item.get("_source_file", "")),
            )
        )
    if len(findings) > limit:
        lines.extend(["", f"其余 {len(findings) - limit} 条请查看 `nuclei.jsonl`。"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize and render Nuclei JSONL results")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    findings, diagnostics = load_findings(args.inputs)
    limit = parse_limit()

    output_jsonl = args.output_dir / "nuclei.jsonl"
    output_jsonl.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in findings),
        encoding="utf-8",
    )

    severities: Counter[str] = Counter()
    templates: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    for item in findings:
        normalized = item["_normalized"]
        severities[normalized["severity"]] += 1
        templates[normalized["template_id"]] += 1
        sources[item.get("_source_file", "unknown")] += 1

    status = {
        "findings": len(findings),
        "severities": dict(severities),
        "unique_templates": len(templates),
        "top_templates": dict(templates.most_common(30)),
        "sources": dict(sources),
        **diagnostics,
    }
    (args.output_dir / "nuclei-status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    report = markdown(findings, limit)
    (args.output_dir / "nuclei-findings.md").write_text(report, encoding="utf-8")

    if args.show:
        print("[Nuclei] 去重后结果：{}".format(len(findings)))
        for item in findings[: min(limit, 30)]:
            value = item["_normalized"]
            print(
                "[Nuclei][{severity}] {template} -> {matched}".format(
                    severity=value["severity"].upper(),
                    template=value["template_id"],
                    matched=value["matched_at"] or value["host"] or "-",
                )
            )
        if len(findings) > 30:
            print("[Nuclei] 其余结果请查看 nuclei-findings.md / nuclei.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
