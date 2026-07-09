#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BEGIN = "<!-- SCANNER_V2_BEGIN -->"
END = "<!-- SCANNER_V2_END -->"


def load_json(path: Path, default: Any) -> Any:
    if not path.is_file() or path.stat().st_size == 0:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return default


def line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())


def cdn_stats(path: Path) -> dict[str, Any]:
    providers: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    records = 0
    if path.is_file():
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            records += 1
            for kind in ("cdn", "cloud", "waf"):
                value = item.get(kind)
                if isinstance(value, bool):
                    if value:
                        kinds[kind] += 1
                elif value:
                    kinds[kind] += 1
                    providers[str(value)] += 1
            provider = item.get("name") or item.get("provider")
            if provider:
                providers[str(provider)] += 1
    return {"records": records, "types": dict(kinds), "providers": dict(providers.most_common(20))}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: enhance_summary.py <result_dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    summary_path = root / "summary.json"
    summary = load_json(summary_path, {})
    if not isinstance(summary, dict):
        summary = {}

    intelligence = load_json(root / "intelligence-stats.json", {})
    url_intelligence = load_json(root / "url-intelligence-stats.json", {})
    content = load_json(root / "content-audit-stats.json", {})
    tls = load_json(root / "tls-stats.json", {})
    cdn = cdn_stats(root / "cdncheck.jsonl")

    summary["scanner_v2"] = {
        "intelligence": intelligence,
        "url_intelligence": url_intelligence,
        "content_audit": content,
        "tls": tls,
        "cdn_cloud_waf": cdn,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    summary_md = root / "summary.md"
    base = summary_md.read_text(encoding="utf-8", errors="ignore") if summary_md.is_file() else "# 扫描结果汇总\n"
    if BEGIN in base:
        base = base.split(BEGIN, 1)[0].rstrip() + "\n"

    lines = [
        "",
        BEGIN,
        "## Scanner V2 资产与 URL 情报",
        "",
        f"- URLFinder URL：{intelligence.get('urlfinder_urls', line_count(root / 'urlfinder.txt'))}",
        f"- GAU 历史 URL：{intelligence.get('gau_urls', line_count(root / 'gau.txt'))}",
        f"- 被动 URL 总数：{intelligence.get('passive_urls', line_count(root / 'passive-urls.raw.txt'))}",
        f"- 历史 URL 存活：{intelligence.get('passive_live_urls', line_count(root / 'passive-live-urls.txt'))}",
        f"- AlterX 范围内候选：{intelligence.get('alterx_candidates', line_count(root / 'alterx.scoped.txt'))}",
        f"- AlterX 有效解析：{intelligence.get('alterx_resolved', line_count(root / 'alterx.resolved.jsonl'))}",
        f"- TLS SAN 新域名：{intelligence.get('tls_san_domains', line_count(root / 'tls-san-domains.txt'))}",
        f"- 回灌新域名：{intelligence.get('enriched_domains', line_count(root / 'enriched-domains.txt'))}",
        f"- 二次爬取 URL：{intelligence.get('secondary_crawl_urls', line_count(root / 'katana.enriched.txt'))}",
        f"- 高优先级 URL：{intelligence.get('priority_urls', line_count(root / 'urls-priority.txt'))}",
        f"- API URL：{intelligence.get('api_urls', line_count(root / 'urls-api.txt'))}",
        f"- 带参数 URL：{intelligence.get('parameterized_urls', line_count(root / 'urls-params.txt'))}",
        f"- 已清空敏感查询值：{url_intelligence.get('redacted_query_values', 0)}",
        f"- 敏感文件 URL：{intelligence.get('sensitive_urls', line_count(root / 'urls-sensitive.txt'))}",
        f"- Sourcemap 二次命中：{intelligence.get('sourcemap_v2_hits', line_count(root / 'sourcemaps.v2.urls.txt'))}",
        f"- FFUF 二次命中：{intelligence.get('ffuf_v2_hits', line_count(root / 'ffuf-v2-hits.txt'))}",
        f"- 最终扫描 URL：{intelligence.get('final_scan_urls', line_count(root / 'scan-urls.txt'))}",
        "",
        "## 内容级泄露与 JavaScript 审计",
        "",
        f"- 请求：{content.get('requested', 0)}",
        f"- 有价值响应：{content.get('interesting', 0)}",
        f"- 泄露特征：{content.get('leak_signatures', 0)}",
        f"- 脱敏密钥指示：{content.get('secret_indicators', 0)}",
        f"- 新接口：{content.get('endpoints', line_count(root / 'content-endpoints.txt'))}",
        f"- 未跟随跳转：{content.get('redirects_not_followed', 0)}",
        f"- 错误：{content.get('errors', 0)}",
        "",
        "详细内容见 `content-findings.md`；疑似密钥只保存脱敏片段，敏感查询值会被清空，HTTP 跳转不自动跟随。",
        "",
        "## TLS、CDN、云与 WAF 情报",
        "",
        f"- TLS SAN：{tls.get('san_domains', 0)}",
        f"- TLS 异常记录：{tls.get('misconfigurations', 0)}",
        f"- CDN/云/WAF 识别记录：{cdn.get('records', 0)}",
    ]
    providers = cdn.get("providers") if isinstance(cdn, dict) else {}
    if isinstance(providers, dict) and providers:
        lines.extend(f"- {name}: {count}" for name, count in providers.items())
    lines.extend(
        [
            "",
            "## Scanner V2 关键结果文件",
            "",
            "- `urls-priority.txt`：优先扫描 URL",
            "- `urls-api.txt`：API、GraphQL、Webhook 和 RPC URL",
            "- `urls-params.txt`：带参数 URL，敏感参数值已清空",
            "- `urls-sensitive.txt`：疑似配置、备份、日志和源码文件",
            "- `sourcemaps.v2.urls.txt`：新增与历史 JavaScript 的 Sourcemap 命中",
            "- `ffuf-v2-hits.txt`：新增资产的高价值路径命中",
            "- `tls-san-domains.txt`：证书 SAN 范围内域名",
            "- `cdncheck.jsonl`：CDN、云和 WAF 分类",
            "- `content-findings.md`：内容级验证结果",
            "- `report.html`：单文件 HTML 总报告",
            END,
            "",
        ]
    )
    summary_md.write_text(base.rstrip() + "\n" + "\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
