#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

from intelligence_common import dump_jsonl, fetch, lines, normalize_url, roots, scoped

METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
DOC_SUFFIXES = ("/swagger.json", "/openapi.json", "/api-docs", "/api-docs.json", "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json")
RISK_WORDS = {"admin": 5, "internal": 5, "debug": 5, "role": 4, "permission": 5, "wallet": 5, "withdraw": 7, "transfer": 6, "settlement": 6, "refund": 6, "payment": 5, "payout": 6, "balance": 5, "password": 4, "token": 4, "secret": 6, "upload": 4, "import": 4, "export": 3, "execute": 6, "config": 4}

def parse_schema(body: bytes, content_type: str, url: str) -> dict[str, Any] | None:
    text = body.decode("utf-8", errors="ignore").lstrip("\ufeff\x00 \t\r\n")
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except Exception:
        pass
    if yaml is not None and ("yaml" in content_type or url.lower().endswith((".yaml", ".yml")) or text.startswith(("openapi:", "swagger:"))):
        try:
            value = yaml.safe_load(text)
            return value if isinstance(value, dict) else None
        except Exception:
            pass
    return None


def schema_servers(doc: dict[str, Any], doc_url: str, scope: list[str]) -> list[str]:
    found: list[str] = []
    for item in doc.get("servers", []) if isinstance(doc.get("servers"), list) else []:
        if isinstance(item, dict) and item.get("url") and "{" not in str(item["url"]):
            value = normalize_url(urljoin(doc_url, str(item["url"])))
            if value and scoped(urlsplit(value).hostname, scope):
                found.append(value.rstrip("/"))
    if not found and doc.get("host"):
        for scheme in doc.get("schemes", []) or [urlsplit(doc_url).scheme]:
            value = normalize_url(f"{scheme}://{doc['host']}{doc.get('basePath') or '/'}")
            if value and scoped(urlsplit(value).hostname, scope):
                found.append(value.rstrip("/"))
    if not found:
        p = urlsplit(doc_url)
        found.append(f"{p.scheme}://{p.netloc}")
    return list(dict.fromkeys(found))[:20]


def operation_security(doc: dict[str, Any], op: dict[str, Any]) -> bool:
    if "security" in op:
        return bool(op.get("security"))
    return bool(doc.get("security"))


def op_score(method: str, path: str, op: dict[str, Any], params: list[dict[str, Any]], secured: bool) -> tuple[int, list[str]]:
    score, reasons = {"post": 2, "put": 3, "patch": 3, "delete": 4}.get(method, 0), []
    if method in {"post", "put", "patch", "delete"}:
        reasons.append("write-method")
    lower = path.lower()
    for word, weight in RISK_WORDS.items():
        if word in lower:
            score += weight
            reasons.append("keyword:" + word)
    names = [str(p.get("name") or "").lower().replace("-", "_") for p in params]
    if any(any(h in name for h in ("token", "secret", "password", "signature", "role", "permission", "user_id", "account_id", "wallet", "amount")) for name in names):
        score += 4
        reasons.append("sensitive-parameters")
    encoded = json.dumps({"requestBody": op.get("requestBody"), "parameters": params}, ensure_ascii=False).lower()
    if any(x in encoded for x in ("multipart/form-data", '"format": "binary"', '"type": "file"')):
        score += 5
        reasons.append("file-upload")
    if op.get("requestBody") or any(str(p.get("in") or "").lower() in {"body", "formdata"} for p in params):
        score += 1
        reasons.append("request-body")
    if not secured:
        score += 5
        reasons.append("no-schema-security")
    if "{" in path:
        score += 1
        reasons.append("object-identifier")
    return score, list(dict.fromkeys(reasons))


def priority(score: int, thresholds: tuple[int, int, int] = (16, 10, 6)) -> str:
    return "P0" if score >= thresholds[0] else "P1" if score >= thresholds[1] else "P2" if score >= thresholds[2] else "P3"


def cmd_api(args: argparse.Namespace) -> int:
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    scope = roots(args.scope_roots or out / "domains.txt")
    seen, candidates, origins = set(), [], set()
    for raw in (v for path in args.inputs for v in lines(path)):
        value = normalize_url(raw)
        if not value or not scoped(urlsplit(value).hostname, scope):
            continue
        p = urlsplit(value)
        origins.add(f"{p.scheme}://{p.netloc}")
        if any(x in p.path.lower() for x in ("swagger", "openapi", "api-docs")) and value not in seen:
            seen.add(value); candidates.append(value)
    for base in sorted(origins):
        for suffix in DOC_SUFFIXES:
            value = base + suffix
            if value not in seen:
                seen.add(value); candidates.append(value)
            if len(candidates) >= args.max_candidates:
                break
        if len(candidates) >= args.max_candidates:
            break
    candidates = candidates[:args.max_candidates]
    (out / "api-schema-candidates.txt").write_text("".join(f"{v}\n" for v in candidates), encoding="utf-8")

    documents, operations, fetches = [], [], []
    def inspect(url: str):
        result = fetch(url, args.timeout, args.max_bytes, args.verify_tls)
        body = result.pop("body", b"")
        doc = parse_schema(body, str(result.get("content_type") or ""), url) if body and result.get("status") == 200 else None
        return result, doc
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 32))) as pool:
        futures = {pool.submit(inspect, url): url for url in candidates}
        for future in as_completed(futures):
            try:
                result, doc = future.result()
            except Exception as exc:
                result, doc = {"url": futures[future], "status": 0, "error": type(exc).__name__}, None
            fetches.append(result)
            if not doc or not isinstance(doc.get("paths"), dict):
                continue
            servers = schema_servers(doc, result["url"], scope)
            info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
            doc_ops = []
            for path, path_item in doc["paths"].items():
                if not isinstance(path_item, dict) or not str(path).startswith("/"):
                    continue
                for method in METHODS:
                    op = path_item.get(method)
                    if not isinstance(op, dict):
                        continue
                    params = [p for source in (path_item.get("parameters"), op.get("parameters")) if isinstance(source, list) for p in source if isinstance(p, dict)]
                    secured = operation_security(doc, op)
                    score, reasons = op_score(method, str(path), op, params, secured)
                    urls = [normalize_url(base.rstrip("/") + "/" + str(path).lstrip("/")) for base in servers]
                    item = {"document_url": result["url"], "method": method.upper(), "path": str(path), "operation_id": str(op.get("operationId") or ""), "summary": str(op.get("summary") or op.get("description") or "")[:500], "tags": [str(x) for x in op.get("tags", [])][:20] if isinstance(op.get("tags"), list) else [], "secured": secured, "parameter_names": [str(p.get("name") or "") for p in params if p.get("name")][:100], "risk_score": score, "priority": priority(score), "risk_reasons": reasons, "urls": [u for u in urls if u]}
                    operations.append(item); doc_ops.append(item)
            schemes = (doc.get("components") or {}).get("securitySchemes", {}) if isinstance(doc.get("components"), dict) else doc.get("securityDefinitions", {})
            documents.append({"url": result["url"], "title": str(info.get("title") or ""), "version": str(doc.get("openapi") or doc.get("swagger") or ""), "api_version": str(info.get("version") or ""), "servers": servers, "security_schemes": sorted(str(k) for k in schemes) if isinstance(schemes, dict) else [], "path_count": len(doc["paths"]), "operation_count": len(doc_ops), "unauthenticated_operations": sum(1 for x in doc_ops if not x["secured"])})
            result["valid_schema"] = True; result["operation_count"] = len(doc_ops)
    dedup = {}
    for item in operations:
        key = (item["method"], item["path"], (item["urls"] or [item["document_url"]])[0])
        if key not in dedup or item["risk_score"] > dedup[key]["risk_score"]:
            dedup[key] = item
    operations = sorted(dedup.values(), key=lambda x: (-x["risk_score"], x["method"], x["path"]))
    dump_jsonl(out / "api-schema-fetch.jsonl", sorted(fetches, key=lambda x: (not bool(x.get("valid_schema")), str(x.get("url")))))
    dump_jsonl(out / "api-schema-documents.jsonl", sorted(documents, key=lambda x: x["url"]))
    dump_jsonl(out / "api-operations.jsonl", operations)
    get_urls = sorted({u for item in operations if item["method"] in {"GET", "HEAD"} for u in item["urls"]})
    (out / "api-operation-urls.txt").write_text("".join(f"{u}\n" for u in get_urls), encoding="utf-8")
    (out / "api-operations-priority.txt").write_text("".join(f"{x['priority']}\t{x['method']}\t{(x['urls'] or [x['path']])[0]}\t{','.join(x['risk_reasons'])}\n" for x in operations if x["priority"] in {"P0", "P1"}), encoding="utf-8")
    stats = {"candidates": len(candidates), "valid_documents": len(documents), "operations": len(operations), "priority_operations": sum(1 for x in operations if x["priority"] in {"P0", "P1"}), "unauthenticated_schema_operations": sum(1 for x in operations if not x["secured"]), "get_operation_urls": len(get_urls), "errors": sum(1 for x in fetches if x.get("error")), "yaml_supported": yaml is not None}
    (out / "api-schema-stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = ["# OpenAPI / Swagger 接口情报", "", f"- 有效文档：{stats['valid_documents']}", f"- 接口操作：{stats['operations']}", f"- P0/P1 操作：{stats['priority_operations']}", f"- 未声明 Schema 鉴权：{stats['unauthenticated_schema_operations']}", "- 未声明 Schema 鉴权只代表文档层信息不足，必须结合真实请求验证。", "", "| 优先级 | 方法 | URL/路径 | Schema 鉴权 | 风险原因 |", "|---|---|---|---|---|"]
    for x in [i for i in operations if i["priority"] in {"P0", "P1"}][:200]:
        md.append(f"| {x['priority']} | `{x['method']}` | `{(x['urls'] or [x['path']])[0]}` | {'是' if x['secured'] else '否/未声明'} | {','.join(x['risk_reasons'])} |")
    (out / "api-schema-findings.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return 0
