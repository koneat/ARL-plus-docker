#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

from intelligence_common import jsonl, load

MD_BEGIN, MD_END = "<!-- ACTIONABLE_INTELLIGENCE_BEGIN -->", "<!-- ACTIONABLE_INTELLIGENCE_END -->"


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def strip_markers(text: str) -> str:
    if MD_BEGIN not in text:
        return text
    before, rest = text.split(MD_BEGIN, 1)
    after = rest.split(MD_END, 1)[1] if MD_END in rest else ""
    return before.rstrip() + "\n" + after.lstrip()


def cmd_report(args: argparse.Namespace) -> int:
    root = args.result_dir
    actionable = load(root / "actionable-stats.json", {})
    api = load(root / "api-schema-stats.json", {})
    delta = load(root / "scan-delta.json", {})
    edge = load(root / "edge-intelligence-stats.json", {})
    assets = list(jsonl(root / "actionable-assets.jsonl"))[:500]
    operations = list(jsonl(root / "api-operations.jsonl"))[:500]
    edge_assets = list(jsonl(root / "edge-assets.jsonl"))[:500]

    summary = load(root / "summary.json", {})
    summary = summary if isinstance(summary, dict) else {}
    v2 = summary.get("scanner_v2") if isinstance(summary.get("scanner_v2"), dict) else {}
    v2.update(
        actionable_intelligence=actionable,
        api_schema=api,
        scan_delta=delta,
        edge_intelligence=edge,
    )
    summary["scanner_v2"] = v2
    (root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    md_lines = [
        MD_BEGIN,
        "## 可行动资产、边缘系统与增量情报",
        "",
        f"- 关联资产：{actionable.get('assets', 0)}",
        f"- P0/P1/P2：{actionable.get('p0', 0)}/{actionable.get('p1', 0)}/{actionable.get('p2', 0)}",
        f"- 边缘资产/非生产环境：{edge.get('assets', 0)}/{edge.get('non_production_assets', 0)}",
        f"- GitHub 配置/Actions：{edge.get('github_config_files', 0)}/{edge.get('github_workflows', 0)}",
        f"- FOFA 结果/敏感配置指示：{edge.get('fofa_results', 0)}/{edge.get('sensitive_indicators', 0)}",
        f"- API 文档/操作：{api.get('valid_documents', 0)}/{api.get('operations', 0)}",
        f"- 新增资产/API/命中：{delta.get('new_items_total', 0)}/{delta.get('new_api_operations', 0)}/{delta.get('new_findings', 0)}",
        "",
        "- `actionable-review.md`：资产画像与人工复核建议",
        "- `edge-review.md`：GitHub/Actions/FOFA 被动边缘系统情报",
        "- `api-schema-findings.md`：OpenAPI/Swagger 高价值操作",
        "- `scan-delta.md`：与上一轮扫描的增量",
        "",
        "注意：FOFA 关联 IP 不自动扩大扫描范围；Schema 未声明 security 不等同于未授权。",
        MD_END,
        "",
    ]
    current_md = (
        (root / "summary.md").read_text(encoding="utf-8", errors="ignore")
        if (root / "summary.md").is_file()
        else "# 扫描结果汇总\n"
    )
    (root / "summary.md").write_text(
        strip_markers(current_md).rstrip() + "\n\n" + "\n".join(md_lines),
        encoding="utf-8",
    )

    report_path = root / "report.html"
    if not report_path.is_file():
        return 0
    report = strip_markers(report_path.read_text(encoding="utf-8", errors="ignore"))

    actionable_rows = []
    for item in [x for x in assets if x.get("priority") in {"P0", "P1", "P2"}][:150]:
        actionable_rows.append(
            f"<tr><td><strong>{esc(item.get('priority'))}</strong></td>"
            f"<td>{esc(item.get('risk_score'))}</td>"
            f"<td><code>{esc(item.get('origin'))}</code></td>"
            f"<td>{esc(', '.join(item.get('categories') or []))}</td>"
            f"<td>{esc(', '.join(item.get('risk_reasons') or [])[:500])}</td>"
            f"<td>{esc('；'.join(item.get('recommended_validation') or [])[:500])}</td></tr>"
        )

    edge_rows = []
    for item in [x for x in edge_assets if x.get("priority") in {"P0", "P1", "P2"}][:150]:
        edge_rows.append(
            f"<tr><td><strong>{esc(item.get('priority'))}</strong></td>"
            f"<td>{esc(item.get('risk_score'))}</td>"
            f"<td><code>{esc(item.get('host'))}</code></td>"
            f"<td>{esc(', '.join(item.get('environments') or []))}</td>"
            f"<td>{esc(', '.join(item.get('components') or []))}</td>"
            f"<td>{esc(', '.join(item.get('sources') or []))}</td>"
            f"<td>{esc(', '.join(item.get('risk_reasons') or [])[:500])}</td></tr>"
        )

    operation_rows = []
    for item in [x for x in operations if x.get("priority") in {"P0", "P1"}][:200]:
        operation_rows.append(
            f"<tr><td><strong>{esc(item.get('priority'))}</strong></td>"
            f"<td><code>{esc(item.get('method'))}</code></td>"
            f"<td><code>{esc((item.get('urls') or [item.get('path')])[0])}</code></td>"
            f"<td>{'是' if item.get('secured') else '否/未声明'}</td>"
            f"<td>{esc(', '.join(item.get('risk_reasons') or []))}</td></tr>"
        )

    section = f"""{MD_BEGIN}
<h2>可行动资产优先级</h2>
<div class="cards">
  <div class="card"><div class="card-title">P0/P1 资产</div><div class="card-value">{int(actionable.get('p0', 0)) + int(actionable.get('p1', 0))}</div><div class="card-sub">证据聚合后的优先复核对象</div></div>
  <div class="card"><div class="card-title">非生产边缘资产</div><div class="card-value">{esc(edge.get('non_production_assets', 0))}</div><div class="card-sub">GitHub/Actions/FOFA 被动情报</div></div>
  <div class="card"><div class="card-title">API 操作</div><div class="card-value">{esc(api.get('operations', 0))}</div><div class="card-sub">来自 OpenAPI/Swagger</div></div>
  <div class="card"><div class="card-title">新增命中</div><div class="card-value">{esc(delta.get('new_findings', 0))}</div><div class="card-sub">基线 {esc(delta.get('baseline') or '无')}</div></div>
</div>
<div class="panel"><table><thead><tr><th>优先级</th><th>分数</th><th>资产</th><th>分类</th><th>证据</th><th>人工验证建议</th></tr></thead><tbody>{''.join(actionable_rows) or '<tr><td colspan="6" class="empty">没有 P0-P2 资产</td></tr>'}</tbody></table></div>
<h2>GitHub / Actions / FOFA 边缘系统</h2>
<div class="panel"><p class="muted">仅保存公开配置与脱敏指示；关联 IP 和历史托管结果不会自动扩大主动扫描范围。</p><table><thead><tr><th>优先级</th><th>分数</th><th>资产</th><th>环境</th><th>开发组件</th><th>来源</th><th>关键原因</th></tr></thead><tbody>{''.join(edge_rows) or '<tr><td colspan="7" class="empty">没有 P0-P2 边缘资产</td></tr>'}</tbody></table></div>
<h2>OpenAPI / Swagger 高价值操作</h2>
<div class="panel"><p class="muted">未声明 Schema 鉴权不等同于未授权，必须进行真实接口差异验证。</p><table><thead><tr><th>优先级</th><th>方法</th><th>URL/路径</th><th>Schema 鉴权</th><th>风险原因</th></tr></thead><tbody>{''.join(operation_rows) or '<tr><td colspan="5" class="empty">没有 P0/P1 API 操作</td></tr>'}</tbody></table></div>
<h2>扫描增量</h2>
<div class="panel"><ul><li>基线：{esc(delta.get('baseline') or '无')}</li><li>新增资产/URL：{esc(delta.get('new_items_total', 0))}</li><li>新增 API 操作：{esc(delta.get('new_api_operations', 0))}</li><li>新增扫描器命中：{esc(delta.get('new_findings', 0))}</li></ul></div>
{MD_END}"""
    anchor = "<h2>Nuclei 命中</h2>"
    report = report.replace(anchor, section + "\n" + anchor, 1) if anchor in report else report.replace("</main>", section + "</main>", 1)

    if "actionable-review.md" not in report:
        report = report.replace(
            '<li><a href="summary.md">summary.md</a></li>',
            '<li><a href="summary.md">summary.md</a></li>'
            '<li><a href="actionable-review.md">actionable-review.md</a></li>'
            '<li><a href="actionable-assets.csv">actionable-assets.csv</a></li>'
            '<li><a href="api-schema-findings.md">api-schema-findings.md</a></li>'
            '<li><a href="scan-delta.md">scan-delta.md</a></li>',
            1,
        )
    if "edge-review.md" not in report:
        report = report.replace(
            '<li><a href="summary.md">summary.md</a></li>',
            '<li><a href="summary.md">summary.md</a></li>'
            '<li><a href="edge-review.md">edge-review.md</a></li>'
            '<li><a href="edge-assets.jsonl">edge-assets.jsonl</a></li>'
            '<li><a href="edge-sensitive-indicators.jsonl">edge-sensitive-indicators.jsonl</a></li>',
            1,
        )
    report_path.write_text(report, encoding="utf-8")
    return 0
