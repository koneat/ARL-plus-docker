#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from intelligence_common import dump_jsonl, jsonl, lines, load, normalize_url, origin

SEV_WEIGHT = {"critical": 100, "high": 65, "medium": 25, "low": 8, "info": 1, "unknown": 0}
CATEGORY_RULES = {
    "admin": r"(?:admin|administrator|manage|management|console|dashboard)",
    "api": r"(?:^|/)(?:api|rest|rpc|graphql|v[0-9]+)(?:/|$)",
    "auth": r"(?:login|signin|signup|oauth|auth|token|password|reset|session)",
    "payment": r"(?:payment|pay|order|refund|settlement|payout|invoice|billing)",
    "wallet": r"(?:wallet|withdraw|transfer|balance|deposit|swap|claim|reward)",
    "internal": r"(?:internal|private|intranet|staff|backoffice)",
    "dev": r"(?:^|[.-])(?:dev|test|testing|staging|stage|uat|preprod|sandbox|beta)(?:[.-]|$)",
    "storage": r"(?:upload|download|export|import|backup|dump|archive|storage|bucket)",
    "observability": r"(?:actuator|metrics|prometheus|debug|trace|logs?|server-status)",
    "api-docs": r"(?:swagger|openapi|api-docs|redoc|graphiql)",
}
CATEGORY_WEIGHT = {"wallet": 18, "payment": 16, "admin": 12, "internal": 12, "auth": 8, "storage": 8, "observability": 7, "dev": 10, "api-docs": 6, "api": 4}

def classify(value: str) -> set[str]:
    return {name for name, pattern in CATEGORY_RULES.items() if re.search(pattern, value, re.I)}


def new_asset(origin_value: str) -> dict[str, Any]:
    p = urlsplit(origin_value)
    return {"origin": origin_value, "host": p.hostname or "", "scheme": p.scheme, "port": p.port or (443 if p.scheme == "https" else 80), "status": set(), "titles": set(), "tech": set(), "servers": set(), "ips": set(), "cnames": set(), "providers": set(), "sources": set(), "categories": set(), "urls": set(), "priority_urls": set(), "api_urls": set(), "param_urls": set(), "sensitive_urls": set(), "js_urls": set(), "sourcemaps": set(), "api_docs": set(), "api_ops": [], "leaks": set(), "secrets": set(), "vulns": [], "tls": set(), "signals": Counter()}


def finding(item: dict[str, Any], scanner: str) -> tuple[str, dict[str, Any]] | None:
    n = item.get("_normalized") if isinstance(item.get("_normalized"), dict) else {}
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    poc = item.get("pocinfo") if isinstance(item.get("pocinfo"), dict) else {}
    target = n.get("matched_at") or item.get("matched-at") or item.get("fulltarget") or item.get("vuln_url") or item.get("host") or item.get("target")
    o = origin(target)
    if not o:
        return None
    sev = str(n.get("severity") or info.get("severity") or poc.get("infoseg") or item.get("vuln_severity") or "unknown").lower()
    return o, {"scanner": scanner, "severity": sev if sev in SEV_WEIGHT else "unknown", "name": str(n.get("name") or info.get("name") or poc.get("infoname") or item.get("vuln_name") or item.get("name") or "finding")[:500], "template": str(n.get("template_id") or item.get("template-id") or item.get("poc_id") or poc.get("id") or "")[:300], "target": normalize_url(target) or str(target)}


def cmd_actionable(args: argparse.Namespace) -> int:
    root: Path = args.result_dir
    assets: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str, str]] = set()
    def asset(o: str):
        return assets.setdefault(o, new_asset(o))
    def add_url(a: dict[str, Any], value: Any, bucket: str = "urls"):
        u = normalize_url(value)
        if u:
            a["urls"].add(u); a[bucket].add(u); a["categories"].update(classify(u))
    def edge(src: str, rel: str, dst: Any, evidence: str):
        if src and dst: edges.add((src, rel, str(dst), evidence))

    for filename in ("httpx.jsonl", "enriched-httpx.jsonl", "passive-httpx.jsonl"):
        for item in jsonl(root / filename):
            o = origin(item.get("url") or item.get("input"))
            if not o: continue
            a = asset(o); a["sources"].add(filename); add_url(a, item.get("url") or item.get("input")); a["categories"].update(classify(a["host"]))
            try: a["status"].add(int(item.get("status_code") or 0))
            except Exception: pass
            if item.get("title"): a["titles"].add(str(item["title"])[:300])
            if item.get("webserver") or item.get("server"): a["servers"].add(str(item.get("webserver") or item.get("server"))[:200])
            tech = item.get("tech") or item.get("technologies") or []
            for v in ([tech] if isinstance(tech, str) else tech if isinstance(tech, list) else []): a["tech"].add(str(v)); edge(a["host"], "uses-technology", v, filename)
            for key, bucket, rel in (("ip", "ips", "resolves-to"), ("cname", "cnames", "cname")):
                vals = item.get(key); vals = vals if isinstance(vals, list) else [vals]
                for v in vals:
                    if v: a[bucket].add(str(v).rstrip(".")); edge(a["host"], rel, v, filename)
            if item.get("cdn"): a["providers"].add("cdn")

    for item in jsonl(root / "url-intelligence.jsonl"):
        o = origin(item.get("url"))
        if not o: continue
        a = asset(o); a["sources"].add("url-intelligence"); add_url(a, item["url"])
        reasons = item.get("reasons") if isinstance(item.get("reasons"), list) else []
        if int(item.get("score") or 0) >= 6: add_url(a, item["url"], "priority_urls")
        if "api" in reasons: add_url(a, item["url"], "api_urls")
        if "parameters" in reasons: add_url(a, item["url"], "param_urls")
        if "sensitive-extension" in reasons or "sensitive-parameter" in reasons: add_url(a, item["url"], "sensitive_urls")
        if "javascript" in reasons: add_url(a, item["url"], "js_urls")
        a["signals"]["url-risk"] = max(a["signals"].get("url-risk", 0), int(item.get("score") or 0)); edge(a["host"], "exposes-url", item["url"], "url-intelligence")
    for filename, bucket in (("urls-priority.txt", "priority_urls"), ("urls-api.txt", "api_urls"), ("urls-params.txt", "param_urls"), ("urls-sensitive.txt", "sensitive_urls"), ("urls-js.txt", "js_urls"), ("sourcemaps.v2.urls.txt", "sourcemaps"), ("api-docs-endpoints.txt", "api_docs")):
        for value in lines(root / filename):
            o = origin(value)
            if o: a = asset(o); a["sources"].add(filename); add_url(a, value, bucket)

    for item in jsonl(root / "content-audit.jsonl"):
        o = origin(item.get("final_url") or item.get("url"))
        if not o: continue
        a = asset(o); a["sources"].add("content-audit"); add_url(a, item.get("final_url") or item.get("url")); a["leaks"].update(str(v) for v in item.get("leak_signatures") or [])
        for v in item.get("secret_indicators") or []: a["secrets"].add(str(v.get("type") if isinstance(v, dict) else v))
        if item.get("interesting"): a["signals"]["interesting-content"] += 1
    for value in lines(root / "content-endpoints.txt"):
        o = origin(value)
        if o: add_url(asset(o), value, "api_urls")

    for item in jsonl(root / "api-operations.jsonl"):
        urls = item.get("urls") if isinstance(item.get("urls"), list) else []
        o = origin((urls or [item.get("document_url")])[0])
        if not o: continue
        a = asset(o); a["sources"].add("api-schema"); a["categories"].update(classify(str(item.get("path") or "")))
        detail = {k: item.get(k) for k in ("priority", "risk_score", "method", "path", "secured", "risk_reasons", "operation_id")}
        if len(a["api_ops"]) < 80: a["api_ops"].append(detail)
        for u in urls: add_url(a, u, "api_urls")
        if item.get("priority") in {"P0", "P1"}: a["signals"]["priority-api"] += 1
        if not item.get("secured"): a["signals"]["schema-no-security"] += 1
        edge(a["host"], "documents-operation", f"{item.get('method')} {item.get('path')}", "api-schema")

    for filename, scanner in (("nuclei.jsonl", "nuclei"), ("afrog.json", "afrog")):
        data = list(jsonl(root / filename)) if filename.endswith("jsonl") else load(root / filename, [])
        if isinstance(data, dict): data = data.get("results") or data.get("data") or data.get("vulnerabilities") or []
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict): continue
            result = finding(item, scanner)
            if result:
                o, f = result; a = asset(o); a["sources"].add(scanner)
                if len(a["vulns"]) < 80: a["vulns"].append(f)
                edge(a["host"], "has-finding", f"{scanner}:{f['template'] or f['name']}", scanner)

    by_host = defaultdict(list)
    for o, a in assets.items(): by_host[a["host"]].append(o)
    for item in jsonl(root / "tls-findings.jsonl"):
        host = str(item.get("host") or item.get("input") or "").lower().strip(".")
        flags = item.get("flags") if isinstance(item.get("flags"), dict) else {}
        for o in by_host.get(host, [f"https://{host}"] if host else []):
            a = asset(o); a["tls"].update(str(k) for k, v in flags.items() if v); a["sources"].add("tlsx")
    for item in jsonl(root / "cdncheck.jsonl"):
        host = str(item.get("host") or item.get("input") or "").lower().strip(".")
        providers = [f"{kind}:{item[key]}" for kind, key in (("cdn", "cdn_name"), ("cloud", "cloud_name"), ("waf", "waf_name")) if item.get(key)]
        for o in by_host.get(host, []): assets[o]["providers"].update(providers); assets[o]["sources"].add("cdncheck")

    def advice(a):
        out = []
        if any(v["severity"] in {"critical", "high"} for v in a["vulns"]): out.append("优先人工复核高危扫描命中，确认请求、响应、版本和真实影响。")
        if a["secrets"]: out.append("核验密钥真实性、权限范围与轮换状态；继续保持脱敏。")
        if a["leaks"]: out.append("确认泄露内容不是统一错误页或伪响应。")
        if a["api_ops"]: out.append("按未登录、低权限、另一账号三组验证对象归属与角色边界。")
        if a["categories"] & {"wallet", "payment"}: out.append("验证金额、订单归属、状态机、重复提交与并发幂等。")
        if a["categories"] & {"admin", "internal"}: out.append("检查垂直越权、前端鉴权和边缘管理接口。")
        if a["sourcemaps"] or a["js_urls"]: out.append("从 Sourcemap/JS 还原隐藏路由和环境域名并回灌测试。")
        return out[:8]
    def serialize(a):
        counts = Counter(v["severity"] for v in a["vulns"]); score, reasons = 0, []
        for sev, count in counts.items(): score += SEV_WEIGHT.get(sev, 0) + min(20, max(0, count-1)*max(1, SEV_WEIGHT.get(sev, 0)//5)); reasons.append(f"{sev}-finding:{count}")
        if a["secrets"]: score += min(70, 30+10*len(a["secrets"])); reasons.append("secret-indicators:"+",".join(sorted(a["secrets"])))
        if a["leaks"]: score += min(45, 18+8*len(a["leaks"])); reasons.append("content-leaks:"+",".join(sorted(a["leaks"])))
        for key, base, each, cap, label in (("priority-api",15,5,55,"priority-api-operations"),("schema-no-security",0,2,25,"schema-no-security")):
            n=int(a["signals"].get(key,0));
            if n: score += min(cap, base+n*each); reasons.append(f"{label}:{n}")
        for values, base, each, cap, label in ((a["sourcemaps"],15,1,30,"sourcemap"),(a["sensitive_urls"],5,2,25,"sensitive-urls"),(a["param_urls"],3,1,15,"parameterized-urls"),(a["tls"],4,3,15,"tls")):
            if values: score += min(cap, base+len(values)*each); reasons.append(f"{label}:{len(values)}")
        if a["api_docs"]: score += 8; reasons.append(f"api-docs:{len(a['api_docs'])}")
        score += min(12, int(a["signals"].get("url-risk",0)))
        for cat in sorted(a["categories"]):
            if CATEGORY_WEIGHT.get(cat): score += CATEGORY_WEIGHT[cat]; reasons.append("category:"+cat)
        if a["ips"] and not a["providers"]: score += 3; reasons.append("direct-origin-metadata")
        p = "P0" if score >= 100 else "P1" if score >= 60 else "P2" if score >= 30 else "P3"
        return {"priority":p,"risk_score":score,"risk_reasons":reasons,"origin":a["origin"],"host":a["host"],"scheme":a["scheme"],"port":a["port"],"status_codes":sorted(a["status"]),"titles":sorted(a["titles"]),"categories":sorted(a["categories"]),"technologies":sorted(a["tech"]),"webservers":sorted(a["servers"]),"ips":sorted(a["ips"]),"cnames":sorted(a["cnames"]),"providers":sorted(a["providers"]),"sources":sorted(a["sources"]),"counts":{"urls":len(a["urls"]),"priority_urls":len(a["priority_urls"]),"api_urls":len(a["api_urls"]),"parameterized_urls":len(a["param_urls"]),"sensitive_urls":len(a["sensitive_urls"]),"javascript_urls":len(a["js_urls"]),"sourcemaps":len(a["sourcemaps"]),"api_docs":len(a["api_docs"]),"api_operations":len(a["api_ops"]),"content_leaks":len(a["leaks"]),"secret_indicators":len(a["secrets"]),"vulnerabilities":len(a["vulns"]),"tls_issues":len(a["tls"])},"vulnerability_severity":dict(counts),"content_leaks":sorted(a["leaks"]),"secret_indicators":sorted(a["secrets"]),"tls_issues":sorted(a["tls"]),"top_urls":sorted(a["priority_urls"]|a["api_urls"]|a["sensitive_urls"])[:80],"sourcemaps":sorted(a["sourcemaps"])[:80],"api_docs":sorted(a["api_docs"])[:80],"api_operations":sorted(a["api_ops"],key=lambda x:-int(x.get("risk_score") or 0))[:80],"vulnerabilities":sorted(a["vulns"],key=lambda x:-SEV_WEIGHT.get(x["severity"],0))[:80],"recommended_validation":advice(a)}
    items = sorted((serialize(a) for a in assets.values()), key=lambda x:(-x["risk_score"],x["origin"]))[:args.max_assets]
    dump_jsonl(root/"actionable-assets.jsonl", items)
    with (root/"actionable-assets.csv").open("w",encoding="utf-8",newline="") as h:
        w=csv.writer(h); w.writerow(["priority","risk_score","origin","host","categories","status_codes","ips","technologies","vulnerabilities","api_operations","secret_indicators","content_leaks","recommended_validation"])
        for x in items: w.writerow([x["priority"],x["risk_score"],x["origin"],x["host"],",".join(x["categories"]),",".join(map(str,x["status_codes"])),",".join(x["ips"]),",".join(x["technologies"]),x["counts"]["vulnerabilities"],x["counts"]["api_operations"],x["counts"]["secret_indicators"],x["counts"]["content_leaks"],"；".join(x["recommended_validation"])])
    targets=[]; seen=set()
    for x in items:
        if x["priority"]=="P3": continue
        for value in [x["origin"]]+x["top_urls"][:14]:
            if value not in seen: seen.add(value); targets.append(value)
    (root/"actionable-targets.txt").write_text("".join(f"{x}\n" for x in targets[:5000]),encoding="utf-8")
    dump_jsonl(root/"asset-relationships.jsonl", ({"from":s,"relation":r,"to":t,"evidence":e} for s,r,t,e in sorted(edges)[:50000]))
    stats={"assets":len(items),"p0":sum(x["priority"]=="P0" for x in items),"p1":sum(x["priority"]=="P1" for x in items),"p2":sum(x["priority"]=="P2" for x in items),"p3":sum(x["priority"]=="P3" for x in items),"relationships":min(len(edges),50000),"actionable_targets":min(len(targets),5000),"assets_with_api_operations":sum(x["counts"]["api_operations"]>0 for x in items),"assets_with_secrets":sum(x["counts"]["secret_indicators"]>0 for x in items),"assets_with_high_findings":sum(x["vulnerability_severity"].get("critical",0)+x["vulnerability_severity"].get("high",0)>0 for x in items)}
    (root/"actionable-stats.json").write_text(json.dumps(stats,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    md=["# 可行动资产情报","",f"- 关联资产：{len(items)}",f"- P0/P1/P2：{stats['p0']}/{stats['p1']}/{stats['p2']}","- 优先级是人工复核顺序，不等同于漏洞严重等级。","","| 优先级 | 分数 | 资产 | 分类 | 关键证据 | 下一步 |","|---|---:|---|---|---|---|"]
    for x in [i for i in items if i["priority"]!="P3"][:200]: md.append(f"| {x['priority']} | {x['risk_score']} | `{x['origin']}` | {','.join(x['categories']) or '-'} | {', '.join(x['risk_reasons'])[:500]} | {'；'.join(x['recommended_validation'])[:500]} |")
    (root/"actionable-review.md").write_text("\n".join(md)+"\n",encoding="utf-8")
    return 0
