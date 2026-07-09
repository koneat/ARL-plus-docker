#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path
from typing import Any

out = Path(sys.argv[1]).resolve()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.open("r", encoding="utf-8", errors="ignore") if line.strip())
    except OSError:
        return 0


nuclei = read_json(out / "nuclei-status.json")
quality = {
    "scanner_v2": True,
    "quality_upgrade": True,
    "legacy_native_restart": False,
    "nuclei": nuclei,
    "coverage": {
        "scope_domains": count_lines(out / "scope-domains.txt"),
        "domains": count_lines(out / "domains.all.txt"),
        "live_urls": count_lines(out / "live-urls.txt"),
        "passive_urls": count_lines(out / "urls-intelligence-all.txt"),
        "priority_urls": count_lines(out / "urls-priority.txt"),
        "katana_urls": count_lines(out / "katana.txt") + count_lines(out / "katana.enriched.txt"),
        "sourcemaps": count_lines(out / "sourcemaps.v2.urls.txt"),
        "ffuf_hits": count_lines(out / "ffuf-v2-hits.txt"),
        "nuclei_findings": count_lines(out / "nuclei.jsonl"),
        "afrog_findings": count_lines(out / "afrog.json"),
    },
}
status = str(nuclei.get("status") or "unknown")
quality["status"] = "degraded" if status.startswith("failed_") else "completed"
quality_path = out / "quality-status.json"
temporary = quality_path.with_suffix(".json.tmp")
temporary.write_text(
    json.dumps(quality, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
os.replace(temporary, quality_path)

report = out / "report.html"
if report.is_file():
    content = report.read_text(encoding="utf-8", errors="ignore")
    if "scanner-v2-quality-banner" not in content:
        badge = "#b91c1c" if quality["status"] == "degraded" else "#166534"
        banner = (
            '<section id="scanner-v2-quality-banner" '
            'style="margin:16px;padding:16px;border:1px solid #d1d5db;border-radius:10px;background:#fff">'
            '<h2 style="margin-top:0">扫描质量状态</h2>'
            f'<p><strong style="color:{badge}">{html.escape(str(quality["status"]))}</strong></p>'
            f'<p>Scanner V2：已启用；Nuclei：{html.escape(status)}；'
            f'目标 URL：{quality["coverage"]["priority_urls"]}；'
            f'Nuclei 命中：{quality["coverage"]["nuclei_findings"]}；'
            f'Afrog 命中：{quality["coverage"]["afrog_findings"]}</p>'
            '<p><a href="quality-status.json">查看结构化质量状态</a> | '
            '<a href="nuclei-status.json">查看 Nuclei 执行状态</a></p>'
            '</section>'
        )
        if "<body" in content and ">" in content[content.find("<body"):]:
            start = content.find("<body")
            end = content.find(">", start)
            content = content[: end + 1] + banner + content[end + 1 :]
        else:
            content = banner + content
        temp_report = report.with_suffix(".html.tmp")
        temp_report.write_text(content, encoding="utf-8")
        os.replace(temp_report, report)
