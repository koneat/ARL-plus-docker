#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            values.append(item)
    return values


def nuclei_data(path: Path) -> tuple[Counter[str], list[dict[str, str]]]:
    severities: Counter[str] = Counter()
    findings: list[dict[str, str]] = []
    for item in load_jsonl(path):
        normalized = item.get("_normalized") if isinstance(item.get("_normalized"), dict) else {}
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = str(normalized.get("severity") or info.get("severity") or "unknown").lower()
        if severity not in SEVERITY_ORDER:
            severity = "unknown"
        severities[severity] += 1
        findings.append(
            {
                "severity": severity,
                "template_id": str(
                    normalized.get("template_id")
                    or item.get("template-id")
                    or item.get("templateID")
                    or "unknown-template"
                ),
                "name": str(normalized.get("name") or info.get("name") or ""),
                "matched_at": str(
                    normalized.get("matched_at")
                    or item.get("matched-at")
                    or item.get("matched")
                    or item.get("host")
                    or ""
                ),
                "source": str(item.get("_source_file") or ""),
            }
        )
    order = {name: index for index, name in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda item: (order.get(item["severity"], 99), item["template_id"], item["matched_at"]))
    return severities, findings


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
            if not isinstance(item, dict):
                continue
            try:
                statuses[int(item.get("status"))] += 1
            except (TypeError, ValueError):
                pass
    return total, statuses


def ordered(counter: Counter[Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in SEVERITY_ORDER:
        if counter.get(key):
            result[key] = counter[key]
    for key, value in sorted(counter.items(), key=lambda item: str(item[0])):
        string_key = str(key)
        if string_key not in result and value:
            result[string_key] = value
    return result


def escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize.py <result_dir>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    target_counts = load_json(root / "target-counts.json", {})
    uncover_stats = load_json(root / "uncover-stats.json", {})
    api_stats = load_json(root / "api-surface-stats.json", {})
    nuclei_status = load_json(root / "nuclei-status.json", {})
    if not isinstance(uncover_stats, dict):
        uncover_stats = {}
    if not isinstance(api_stats, dict):
        api_stats = {}
    if not isinstance(nuclei_status, dict):
        nuclei_status = {}

    nuclei, nuclei_findings = nuclei_data(root / "nuclei.jsonl")
    afrog = afrog_severities(root / "afrog.json")
    ffuf_total, ffuf_statuses = ffuf_summary(root / "ffuf")

    errors: list[str] = []
    error_path = root / "errors.log"
    if error_path.is_file():
        errors = [line.strip() for line in error_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]

    summary = {
        "targets": target_counts,
        "uncover": uncover_stats,
        "api_surface": api_stats,
        "nuclei_status": nuclei_status,
        "external_hosts_discovered": line_count(root / "uncover-hosts.txt"),
        "external_services_discovered": line_count(root / "uncover-services.txt"),
        "external_urls_discovered": line_count(root / "uncover-urls.txt"),
        "external_ip_candidates": line_count(root / "uncover-ip-candidates.txt"),
        "subdomains_discovered": line_count(root / "subfinder.txt"),
        "resolved_domains": line_count(root / "dnsx.jsonl"),
        "open_services": line_count(root / "open-services.txt"),
        "live_urls": line_count(root / "live-urls.txt"),
        "crawled_urls": line_count(root / "katana.txt"),
        "api_endpoints": line_count(root / "api-endpoints.txt"),
        "api_docs": line_count(root / "api-docs-endpoints.txt"),
        "webhooks": line_count(root / "webhook-endpoints.txt"),
        "websockets": line_count(root / "websocket-endpoints.txt"),
        "javascript_files": line_count(root / "js-files.txt"),
        "sourcemaps": line_count(root / "sourcemaps.jsonl"),
        "total_scan_urls": line_count(root / "scan-urls.txt"),
        "nuclei_findings": ordered(nuclei),
        "nuclei_finding_details": nuclei_findings[:100],
        "afrog_findings": ordered(afrog),
        "ffuf_findings": ffuf_total,
        "ffuf_statuses": {str(k): v for k, v in sorted(ffuf_statuses.items())},
        "stage_errors": errors,
    }

    (root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    uncover_status = str(uncover_stats.get("status") or "completed")
    sources = uncover_stats.get("sources") or {}
    template_count = 0
    template_status = root / "nuclei-template-status.txt"
    if template_status.is_file():
        for line in template_status.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("template_count="):
                try:
                    template_count = int(line.split("=", 1)[1])
                except ValueError:
                    pass

    lines = [
        "# 扫描结果汇总",
        "",
        f"- 规范化目标：{target_counts.get('normalized', 0)}",
        f"- 外部搜索引擎发现域名：{summary['external_hosts_discovered']}",
        f"- 外部搜索引擎发现服务：{summary['external_services_discovered']}",
        f"- 外部搜索引擎发现 URL：{summary['external_urls_discovered']}",
        f"- 待人工确认 IP：{summary['external_ip_candidates']}",
        f"- 被动发现子域名：{summary['subdomains_discovered']}",
        f"- DNS 有效记录：{summary['resolved_domains']}",
        f"- 开放服务：{summary['open_services']}",
        f"- 存活 URL：{summary['live_urls']}",
        f"- 爬取 URL：{summary['crawled_urls']}",
        f"- API/HTTP 调用端点：{summary['api_endpoints']}",
        f"- API 文档入口：{summary['api_docs']}",
        f"- Webhook/Callback：{summary['webhooks']}",
        f"- WebSocket：{summary['websockets']}",
        f"- JavaScript 文件：{summary['javascript_files']}",
        f"- Sourcemap 泄露：{summary['sourcemaps']}",
        f"- 最终漏洞扫描 URL：{summary['total_scan_urls']}",
        "",
        "## 外部资产聚合",
        "",
        f"- 状态：{uncover_status}",
    ]
    if isinstance(sources, dict) and sources:
        lines.extend(f"- {key}: {value}" for key, value in sorted(sources.items()))
    else:
        lines.append("- 未配置、未运行或没有返回结果")

    lines.extend(["", "## Nuclei", "", f"- 模板数量：{template_count}", f"- 去重后结果：{len(nuclei_findings)}"])
    if summary["nuclei_findings"]:
        lines.extend(f"- {key}: {value}" for key, value in summary["nuclei_findings"].items())
        lines.extend(
            [
                "",
                "### 具体命中",
                "",
                "| 严重级别 | 模板 | 名称 | 命中位置 |",
                "|---|---|---|---|",
            ]
        )
        for item in nuclei_findings[:30]:
            lines.append(
                "| {severity} | `{template}` | {name} | `{matched}` |".format(
                    severity=escape_table(item["severity"]),
                    template=escape_table(item["template_id"]),
                    name=escape_table(item["name"] or "-"),
                    matched=escape_table(item["matched_at"] or "-"),
                )
            )
        if len(nuclei_findings) > 30:
            lines.extend(["", f"其余 {len(nuclei_findings) - 30} 条见 `nuclei-findings.md`。"])
    else:
        lines.extend(
            [
                "- 未发现结果或该阶段未成功运行",
                "- 排查文件：`nuclei-status.json`、`nuclei-template-status.txt`、`nuclei.*.log`",
            ]
        )

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
            f"- Nuclei 文件泄露/错误配置专项：{nuclei_status.get('sources', {}).get('nuclei.exposure.jsonl', 0) if isinstance(nuclei_status.get('sources'), dict) else 0}",
            f"- Nuclei API 调用面专项：{nuclei_status.get('sources', {}).get('nuclei.api.jsonl', 0) if isinstance(nuclei_status.get('sources'), dict) else 0}",
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
