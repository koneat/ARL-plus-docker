#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
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
DOC_SUFFIXES = (
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api-docs",
    "/api-docs.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
)
RISK_WORDS = {
    "admin": 5,
    "internal": 5,
    "debug": 5,
    "role": 4,
    "permission": 5,
    "wallet": 5,
    "withdraw": 7,
    "transfer": 6,
    "settlement": 6,
    "refund": 6,
    "payment": 5,
    "payout": 6,
    "balance": 5,
    "password": 4,
    "token": 4,
    "secret": 6,
    "upload": 4,
    "import": 4,
    "export": 3,
    "execute": 6,
    "config": 4,
}


def parse_schema(body: bytes, content_type: str, url: str) -> dict[str, Any] | None:
    text = body.decode("utf-8", errors="ignore").lstrip("\ufeff\x00 \t\r\n")
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except Exception:
        pass
    if yaml is not None and (
        "yaml" in content_type
        or url.lower().endswith((".yaml", ".yml"))
        or text.startswith(("openapi:", "swagger:"))
    ):
        try:
            value = yaml.safe_load(text)
            return value if isinstance(value, dict) else None
        except Exception:
            pass
    return None


def is_ip(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def host_allowed(host: str | None, scope: list[str], exact_ip_hosts: set[str]) -> bool:
    if not host:
        return False
    candidate = host.lower().strip(".").strip("[]")
    return scoped(candidate, scope) if scope else candidate in exact_ip_hosts


def schema_servers(
    doc: dict[str, Any],
    doc_url: str,
    scope: list[str],
    exact_ip_hosts: set[str],
) -> list[str]:
    found: list[str] = []
    for item in doc.get("servers", []) if isinstance(doc.get("servers"), list) else []:
        if isinstance(item, dict) and item.get("url") and "{" not in str(item["url"]):
            value = normalize_url(urljoin(doc_url, str(item["url"])))
            if value and host_allowed(urlsplit(value).hostname, scope, exact_ip_hosts):
                found.append(value.rstrip("/"))

    if not found and doc.get("host"):
        for scheme in doc.get("schemes", []) or [urlsplit(doc_url).scheme]:
            value = normalize_url(f"{scheme}://{doc['host']}{doc.get('basePath') or '/'}")
            if value and host_allowed(urlsplit(value).hostname, scope, exact_ip_hosts):
                found.append(value.rstrip("/"))

    if not found:
        parsed = urlsplit(doc_url)
        base_path = str(doc.get("basePath") or "/")
        fallback = normalize_url(urljoin(f"{parsed.scheme}://{parsed.netloc}/", base_path.lstrip("/")))
        if fallback and host_allowed(urlsplit(fallback).hostname, scope, exact_ip_hosts):
            found.append(fallback.rstrip("/"))

    return list(dict.fromkeys(found))[:20]


def operation_security(doc: dict[str, Any], op: dict[str, Any]) -> bool:
    if "security" in op:
        return bool(op.get("security"))
    return bool(doc.get("security"))


def op_score(
    method: str,
    path: str,
    op: dict[str, Any],
    params: list[dict[str, Any]],
    secured: bool,
) -> tuple[int, list[str]]:
    score, reasons = {"post": 2, "put": 3, "patch": 3, "delete": 4}.get(method, 0), []
    if method in {"post", "put", "patch", "delete"}:
        reasons.append("write-method")
    lower = path.lower()
    for word, weight in RISK_WORDS.items():
        if word in lower:
            score += weight
            reasons.append("keyword:" + word)
    names = [str(p.get("name") or "").lower().replace("-", "_") for p in params]
    if any(
        any(
            hint in name
            for hint in (
                "token",
                "secret",
                "password",
                "signature",
                "role",
                "permission",
                "user_id",
                "account_id",
                "wallet",
                "amount",
            )
        )
        for name in names
    ):
        score += 4
        reasons.append("sensitive-parameters")
    encoded = json.dumps(
        {"requestBody": op.get("requestBody"), "parameters": params},
        ensure_ascii=False,
    ).lower()
    if any(x in encoded for x in ("multipart/form-data", '"format": "binary"', '"type": "file"')):
        score += 5
        reasons.append("file-upload")
    if op.get("requestBody") or any(
        str(p.get("in") or "").lower() in {"body", "formdata"} for p in params
    ):
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


def concrete_operation_url(value: str | None) -> bool:
    return bool(value and "{" not in value and "}" not in value)


def cmd_api(args: argparse.Namespace) -> int:
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    scope = roots(args.scope_roots or out / "domains.txt")

    normalized_inputs: list[str] = []
    exact_ip_hosts: set[str] = set()
    for path in args.inputs:
        for raw in lines(path):
            value = normalize_url(raw)
            if not value:
                continue
            normalized_inputs.append(value)
            host = urlsplit(value).hostname
            if is_ip(host):
                exact_ip_hosts.add(str(host).lower().strip("[]"))

    seen: set[str] = set()
    candidates: list[str] = []
    origins: set[str] = set()
    for value in normalized_inputs:
        parsed = urlsplit(value)
        if not host_allowed(parsed.hostname, scope, exact_ip_hosts):
            continue
        origins.add(f"{parsed.scheme}://{parsed.netloc}")
        if any(x in parsed.path.lower() for x in ("swagger", "openapi", "api-docs")) and value not in seen:
            seen.add(value)
            candidates.append(value)

    for base in sorted(origins):
        for suffix in DOC_SUFFIXES:
            value = base + suffix
            if value not in seen:
                seen.add(value)
                candidates.append(value)
            if len(candidates) >= args.max_candidates:
                break
        if len(candidates) >= args.max_candidates:
            break

    candidates = candidates[: args.max_candidates]
    (out / "api-schema-candidates.txt").write_text(
        "".join(f"{value}\n" for value in candidates),
        encoding="utf-8",
    )

    documents: list[dict[str, Any]] = []
    operations: list[dict[str, Any]] = []
    fetches: list[dict[str, Any]] = []

    def inspect(url: str):
        result = fetch(url, args.timeout, args.max_bytes, args.verify_tls)
        body = result.pop("body", b"")
        doc = (
            parse_schema(body, str(result.get("content_type") or ""), url)
            if body and result.get("status") == 200
            else None
        )
        return result, doc

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 32))) as pool:
        futures = {pool.submit(inspect, url): url for url in candidates}
        for future in as_completed(futures):
            try:
                result, doc = future.result()
            except Exception as exc:
                result, doc = {
                    "url": futures[future],
                    "status": 0,
                    "error": type(exc).__name__,
                }, None
            fetches.append(result)
            if not doc or not isinstance(doc.get("paths"), dict):
                continue

            servers = schema_servers(doc, result["url"], scope, exact_ip_hosts)
            if not servers:
                result["error"] = "no-in-scope-server"
                continue
            info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
            doc_ops: list[dict[str, Any]] = []
            for path, path_item in doc["paths"].items():
                if not isinstance(path_item, dict) or not str(path).startswith("/"):
                    continue
                for method in METHODS:
                    op = path_item.get(method)
                    if not isinstance(op, dict):
                        continue
                    params = [
                        parameter
                        for source in (path_item.get("parameters"), op.get("parameters"))
                        if isinstance(source, list)
                        for parameter in source
                        if isinstance(parameter, dict)
                    ]
                    secured = operation_security(doc, op)
                    score, reasons = op_score(method, str(path), op, params, secured)
                    urls = [
                        normalize_url(base.rstrip("/") + "/" + str(path).lstrip("/"))
                        for base in servers
                    ]
                    item = {
                        "document_url": result["url"],
                        "method": method.upper(),
                        "path": str(path),
                        "operation_id": str(op.get("operationId") or ""),
                        "summary": str(op.get("summary") or op.get("description") or "")[:500],
                        "tags": [str(x) for x in op.get("tags", [])][:20]
                        if isinstance(op.get("tags"), list)
                        else [],
                        "secured": secured,
                        "parameter_names": [
                            str(parameter.get("name") or "")
                            for parameter in params
                            if parameter.get("name")
                        ][:100],
                        "risk_score": score,
                        "priority": priority(score),
                        "risk_reasons": reasons,
                        "urls": [url for url in urls if url],
                    }
                    operations.append(item)
                    doc_ops.append(item)

            schemes = (
                (doc.get("components") or {}).get("securitySchemes", {})
                if isinstance(doc.get("components"), dict)
                else doc.get("securityDefinitions", {})
            )
            documents.append(
                {
                    "url": result["url"],
                    "title": str(info.get("title") or ""),
                    "version": str(doc.get("openapi") or doc.get("swagger") or ""),
                    "api_version": str(info.get("version") or ""),
                    "servers": servers,
                    "security_schemes": sorted(str(key) for key in schemes)
                    if isinstance(schemes, dict)
                    else [],
                    "path_count": len(doc["paths"]),
                    "operation_count": len(doc_ops),
                    "unauthenticated_operations": sum(1 for item in doc_ops if not item["secured"]),
                }
            )
            result["valid_schema"] = True
            result["operation_count"] = len(doc_ops)

    deduplicated: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in operations:
        key = (
            item["method"],
            item["path"],
            (item["urls"] or [item["document_url"]])[0],
        )
        if key not in deduplicated or item["risk_score"] > deduplicated[key]["risk_score"]:
            deduplicated[key] = item
    operations = sorted(
        deduplicated.values(),
        key=lambda item: (-item["risk_score"], item["method"], item["path"]),
    )

    dump_jsonl(
        out / "api-schema-fetch.jsonl",
        sorted(fetches, key=lambda item: (not bool(item.get("valid_schema")), str(item.get("url")))),
    )
    dump_jsonl(out / "api-schema-documents.jsonl", sorted(documents, key=lambda item: item["url"]))
    dump_jsonl(out / "api-operations.jsonl", operations)

    get_urls = sorted(
        {
            url
            for item in operations
            if item["method"] in {"GET", "HEAD"}
            for url in item["urls"]
            if concrete_operation_url(url)
        }
    )
    skipped_template_urls = sum(
        1
        for item in operations
        if item["method"] in {"GET", "HEAD"}
        for url in item["urls"]
        if not concrete_operation_url(url)
    )
    (out / "api-operation-urls.txt").write_text(
        "".join(f"{url}\n" for url in get_urls),
        encoding="utf-8",
    )
    (out / "api-operations-priority.txt").write_text(
        "".join(
            f"{item['priority']}\t{item['method']}\t{(item['urls'] or [item['path']])[0]}\t{','.join(item['risk_reasons'])}\n"
            for item in operations
            if item["priority"] in {"P0", "P1"}
        ),
        encoding="utf-8",
    )

    stats = {
        "candidates": len(candidates),
        "valid_documents": len(documents),
        "operations": len(operations),
        "priority_operations": sum(1 for item in operations if item["priority"] in {"P0", "P1"}),
        "unauthenticated_schema_operations": sum(1 for item in operations if not item["secured"]),
        "get_operation_urls": len(get_urls),
        "skipped_template_operation_urls": skipped_template_urls,
        "scope_domains": len(scope),
        "scope_ip_hosts": len(exact_ip_hosts),
        "errors": sum(1 for item in fetches if item.get("error")),
        "yaml_supported": yaml is not None,
    }
    (out / "api-schema-stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    markdown = [
        "# OpenAPI / Swagger 接口情报",
        "",
        f"- 有效文档：{stats['valid_documents']}",
        f"- 接口操作：{stats['operations']}",
        f"- P0/P1 操作：{stats['priority_operations']}",
        f"- 未声明 Schema 鉴权：{stats['unauthenticated_schema_operations']}",
        f"- 未回灌的路径模板 URL：{stats['skipped_template_operation_urls']}",
        "- 未声明 Schema 鉴权只代表文档层信息不足，必须结合真实请求验证。",
        "",
        "| 优先级 | 方法 | URL/路径 | Schema 鉴权 | 风险原因 |",
        "|---|---|---|---|---|",
    ]
    for item in [value for value in operations if value["priority"] in {"P0", "P1"}][:200]:
        markdown.append(
            f"| {item['priority']} | `{item['method']}` | `{(item['urls'] or [item['path']])[0]}` | "
            f"{'是' if item['secured'] else '否/未声明'} | {','.join(item['risk_reasons'])} |"
        )
    (out / "api-schema-findings.md").write_text(
        "\n".join(markdown) + "\n",
        encoding="utf-8",
    )
    return 0
