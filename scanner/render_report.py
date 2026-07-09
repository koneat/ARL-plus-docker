#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any

SEVERITY_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
    "unknown": "sev-unknown",
}


def load_json(path: Path, default: Any) -> Any:
    if not path.is_file() or path.stat().st_size == 0:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return default


def load_jsonl(path: Path, limit: int = 500) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if not path.is_file():
        return result
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            result.append(item)
            if len(result) >= limit:
                break
    return result


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def card(title: str, value: Any, subtitle: str = "") -> str:
    return f'<div class="card"><div class="card-title">{esc(title)}</div><div class="card-value">{esc(value)}</div><div class="card-sub">{esc(subtitle)}</div></div>'


def nuclei_rows(items: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for item in items[:200]:
        normalized = item.get("_normalized") if isinstance(item.get("_normalized"), dict) else {}
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = str(normalized.get("severity") or info.get("severity") or "unknown").lower()
        template_id = normalized.get("template_id") or item.get("template-id") or item.get("templateID") or "unknown-template"
        name = normalized.get("name") or info.get("name") or ""
        matched = normalized.get("matched_at") or item.get("matched-at") or item.get("host") or ""
        source = item.get("_source_file") or ""
        rows.append(
            "<tr>"
            f'<td><span class="badge {SEVERITY_CLASS.get(severity, "sev-unknown")}">{esc(severity)}</span></td>'
            f"<td><code>{esc(template_id)}</code></td>"
            f"<td>{esc(name)}</td>"
            f"<td><code>{esc(matched)}</code></td>"
            f"<td>{esc(source)}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="5" class="empty">没有 Nuclei 命中</td></tr>'


def content_rows(items: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for item in items:
        if not item.get("interesting"):
            continue
        signatures = ", ".join(item.get("leak_signatures") or []) or "-"
        secret_count = len(item.get("secret_indicators") or [])
        endpoint_count = int(item.get("endpoint_count") or 0)
        rows.append(
            "<tr>"
            f"<td><code>{esc(item.get('final_url') or item.get('url') or '')}</code></td>"
            f"<td>{esc(item.get('status', 0))}</td>"
            f"<td>{esc(signatures)}</td>"
            f"<td>{secret_count}</td>"
            f"<td>{endpoint_count}</td>"
            "</tr>"
        )
        if len(rows) >= 150:
            break
    return "".join(rows) or '<tr><td colspan="5" class="empty">没有内容级泄露命中</td></tr>'


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: render_report.py <result_dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    summary = load_json(root / "summary.json", {})
    scanner_v2 = summary.get("scanner_v2") if isinstance(summary, dict) else {}
    scanner_v2 = scanner_v2 if isinstance(scanner_v2, dict) else {}
    intelligence = scanner_v2.get("intelligence") if isinstance(scanner_v2.get("intelligence"), dict) else {}
    content_stats = scanner_v2.get("content_audit") if isinstance(scanner_v2.get("content_audit"), dict) else {}
    tls_stats = scanner_v2.get("tls") if isinstance(scanner_v2.get("tls"), dict) else {}
    cdn_stats = scanner_v2.get("cdn_cloud_waf") if isinstance(scanner_v2.get("cdn_cloud_waf"), dict) else {}
    nuclei = load_jsonl(root / "nuclei.jsonl", 500)
    content = load_jsonl(root / "content-audit.jsonl", 500)
    manifest = root / "manifest.txt"
    manifest_text = manifest.read_text(encoding="utf-8", errors="ignore") if manifest.is_file() else ""

    nuclei_counts = summary.get("nuclei_findings", {}) if isinstance(summary, dict) else {}
    nuclei_counts = nuclei_counts if isinstance(nuclei_counts, dict) else {}
    errors = summary.get("stage_errors", []) if isinstance(summary, dict) else []
    errors = errors if isinstance(errors, list) else []

    cards = "".join(
        [
            card("存活 URL", summary.get("live_urls", 0), "HTTPX 与新增资产"),
            card("最终扫描 URL", intelligence.get("final_scan_urls", summary.get("total_scan_urls", 0)), "风险排序后"),
            card("高优先级 URL", intelligence.get("priority_urls", 0), "管理、API、配置、备份"),
            card("API URL", intelligence.get("api_urls", 0), "API/GraphQL/Webhook/RPC"),
            card("新增域名", intelligence.get("enriched_domains", 0), "TLS SAN 与排列回灌"),
            card("内容泄露", content_stats.get("interesting", 0), "内容级验证"),
            card("Nuclei 严重/高危", int(nuclei_counts.get("critical", 0)) + int(nuclei_counts.get("high", 0)), "去重后"),
            card("阶段错误", len(errors), "非阻断式执行"),
        ]
    )

    provider_rows = "".join(
        f"<tr><td>{esc(name)}</td><td>{esc(count)}</td></tr>"
        for name, count in (cdn_stats.get("providers") or {}).items()
    ) or '<tr><td colspan="2" class="empty">没有识别结果</td></tr>'

    error_items = "".join(f"<li><code>{esc(item)}</code></li>" for item in errors) or "<li>无</li>"

    document = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARL Plus Scanner V2 报告</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2e;--panel2:#18233d;--text:#e9eefb;--muted:#9aabc8;--line:#2a3858;--accent:#65a7ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1500px;margin:auto;padding:28px}}h1{{margin:0 0 6px;font-size:30px}}h2{{margin:30px 0 12px;font-size:20px}}.muted{{color:var(--muted)}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:20px}}.card{{background:linear-gradient(145deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:12px;padding:16px}}
.card-title{{color:var(--muted)}}.card-value{{font-size:30px;font-weight:750;margin:4px 0}}.card-sub{{color:var(--muted);font-size:12px}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:720px}}th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{position:sticky;top:0;background:var(--panel2)}}code{{color:#b9d6ff;word-break:break-all}}
.badge{{display:inline-block;border-radius:999px;padding:2px 8px;font-size:12px;font-weight:700}}.sev-critical{{background:#6b1022;color:#ffd6de}}.sev-high{{background:#74260d;color:#ffe1d3}}.sev-medium{{background:#725a0a;color:#fff0b3}}.sev-low{{background:#154d57;color:#c8f6ff}}.sev-info{{background:#233e73;color:#d9e7ff}}.sev-unknown{{background:#414a5c;color:#eef2fa}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}@media(max-width:900px){{.grid2{{grid-template-columns:1fr}}main{{padding:16px}}}}.empty{{color:var(--muted);text-align:center}}ul{{margin:0;padding-left:20px}}a{{color:var(--accent)}}pre{{white-space:pre-wrap;word-break:break-word;color:#c4d4ef}}
</style>
</head>
<body><main>
<h1>ARL Plus Scanner V2</h1>
<div class="muted">资产聚合、历史 URL、TLS SAN、子域名排列、内容级泄露验证、智能风险排序与多策略 Nuclei</div>
<div class="cards">{cards}</div>

<h2>Nuclei 命中</h2>
<div class="panel"><table><thead><tr><th>级别</th><th>模板</th><th>名称</th><th>命中位置</th><th>来源</th></tr></thead><tbody>{nuclei_rows(nuclei)}</tbody></table></div>

<h2>内容级泄露与 JavaScript 接口</h2>
<div class="panel"><table><thead><tr><th>URL</th><th>状态</th><th>泄露特征</th><th>密钥指示</th><th>新接口</th></tr></thead><tbody>{content_rows(content)}</tbody></table></div>

<div class="grid2">
<section><h2>TLS 与网络情报</h2><div class="panel"><ul>
<li>TLS SAN 域名：{esc(tls_stats.get('san_domains', 0))}</li>
<li>TLS 异常记录：{esc(tls_stats.get('misconfigurations', 0))}</li>
<li>CDN/云/WAF 记录：{esc(cdn_stats.get('records', 0))}</li>
<li>开放服务：{esc(summary.get('open_services', 0))}</li>
</ul></div></section>
<section><h2>CDN / 云 / WAF 提供方</h2><div class="panel"><table><thead><tr><th>提供方</th><th>数量</th></tr></thead><tbody>{provider_rows}</tbody></table></div></section>
</div>

<h2>阶段错误</h2><div class="panel"><ul>{error_items}</ul></div>
<h2>运行清单</h2><div class="panel"><pre>{esc(manifest_text)}</pre></div>
<h2>结果文件</h2><div class="panel"><ul>
<li><a href="summary.md">summary.md</a></li><li><a href="summary.json">summary.json</a></li><li><a href="nuclei-findings.md">nuclei-findings.md</a></li><li><a href="content-findings.md">content-findings.md</a></li><li><a href="urls-priority.txt">urls-priority.txt</a></li><li><a href="urls-api.txt">urls-api.txt</a></li><li><a href="urls-sensitive.txt">urls-sensitive.txt</a></li><li><a href="tls-san-domains.txt">tls-san-domains.txt</a></li>
</ul></div>
</main></body></html>"""
    (root / "report.html").write_text(document, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
