#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

USER_AGENT = "ARL-Plus-Scanner/2.0 authorized-security-assessment"
MAX_REDIRECTS = 5
LOCK = threading.Lock()

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\b")),
    ("github-token", re.compile(r"\b(?:ghp|github_pat|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    ("generic-secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*['\"]?([^'\"\s,;}]{8,})")),
]

ENDPOINT_PATTERNS = [
    re.compile(r"(?P<quote>['\"])(?P<value>https?://[^'\"\s]{4,}|wss?://[^'\"\s]{4,})(?P=quote)"),
    re.compile(r"(?P<quote>['\"])(?P<value>/(?:api|rest|rpc|graphql|webhook|callback|oauth|auth|admin|internal|v[0-9]+)(?:/[^'\"\s]*)?)(?P=quote)", re.I),
]

LEAK_SIGNATURES: list[tuple[str, re.Pattern[bytes]]] = [
    ("dotenv", re.compile(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*[^\r\n]{1,500}$")),
    ("git-head", re.compile(rb"(?m)^ref:\s+refs/heads/")),
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("sql-dump", re.compile(rb"(?i)(?:CREATE\s+TABLE|INSERT\s+INTO|PostgreSQL database dump|MySQL dump)")),
    ("source-map", re.compile(rb'"sources"\s*:\s*\[')),
    ("spring-config", re.compile(rb"(?m)^(?:spring\.|server\.|management\.|datasource\.)")),
    ("cloud-credentials", re.compile(rb"(?i)(?:aws_access_key_id|private_key_id|client_email|tenantId|subscriptionId)")),
]

TEXT_TYPES = (
    "text/", "application/json", "application/javascript", "application/x-javascript", "application/xml",
    "application/yaml", "application/x-yaml", "application/octet-stream",
)


def redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "…" + value[-4:]


def load_urls(paths: list[Path], limit: int) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = raw.strip()
            if not value or value in seen:
                continue
            try:
                parsed = urlsplit(value)
            except ValueError:
                continue
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            seen.add(value)
            result.append(value)
            if len(result) >= limit:
                return result
    return result


def request_url(url: str, timeout: int, max_bytes: int, verify_tls: bool) -> dict[str, Any]:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urlopen(req, timeout=timeout, context=context) as response:
            status = int(getattr(response, "status", 200))
            final_url = response.geturl()
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > max_bytes * 4:
                        return {"url": url, "final_url": final_url, "status": status, "skipped": "content-length", "content_type": content_type}
                except ValueError:
                    pass
            body = response.read(max_bytes + 1)
            truncated = len(body) > max_bytes
            body = body[:max_bytes]
            return {
                "url": url,
                "final_url": final_url,
                "status": status,
                "content_type": content_type,
                "body": body,
                "truncated": truncated,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
    except HTTPError as exc:
        return {"url": url, "status": int(exc.code), "error": "http-error"}
    except (URLError, TimeoutError, ssl.SSLError, OSError, ValueError) as exc:
        return {"url": url, "status": 0, "error": type(exc).__name__}


def analyze(result: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    body = result.pop("body", b"")
    if not isinstance(body, bytes) or not body:
        return result, set()
    content_type = str(result.get("content_type") or "")
    is_text = any(content_type.startswith(prefix) for prefix in TEXT_TYPES) or b"\x00" not in body[:4096]
    leak_types = [name for name, pattern in LEAK_SIGNATURES if pattern.search(body)]
    endpoints: set[str] = set()
    secrets: list[dict[str, str]] = []
    if is_text:
        text = body.decode("utf-8", errors="ignore")
        for name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(1) if match.lastindex else match.group(0)
                secrets.append({"type": name, "redacted": redact(raw)})
                if len(secrets) >= 20:
                    break
            if len(secrets) >= 20:
                break
        base = str(result.get("final_url") or result.get("url") or "")
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group("value").strip()
                if value.startswith("/"):
                    value = urljoin(base, value)
                try:
                    parsed = urlsplit(value)
                except ValueError:
                    continue
                base_host = urlsplit(base).hostname
                if parsed.scheme in {"http", "https", "ws", "wss"} and parsed.hostname == base_host:
                    endpoints.add(value)
                if len(endpoints) >= 500:
                    break
    result["leak_signatures"] = leak_types
    result["secret_indicators"] = secrets
    result["endpoint_count"] = len(endpoints)
    result["interesting"] = bool(leak_types or secrets or endpoints)
    return result, endpoints


def markdown(findings: list[dict[str, Any]]) -> str:
    interesting = [item for item in findings if item.get("interesting")]
    lines = [
        "# 内容级泄露与 JavaScript 审计",
        "",
        f"- 请求总数：{len(findings)}",
        f"- 有价值响应：{len(interesting)}",
        "- 所有疑似密钥仅显示脱敏片段，不在报告中保存完整值。",
        "",
    ]
    if not interesting:
        lines.append("未发现内容级泄露特征或新增接口。")
        lines.append("")
        return "\n".join(lines)
    lines.extend(["| URL | 状态 | 泄露特征 | 密钥指示 | 新接口 |", "|---|---:|---|---:|---:|"])
    for item in interesting[:100]:
        url = str(item.get("final_url") or item.get("url") or "").replace("|", "\\|")
        signatures = ",".join(item.get("leak_signatures") or []) or "-"
        secrets = len(item.get("secret_indicators") or [])
        endpoints = int(item.get("endpoint_count") or 0)
        lines.append(f"| `{url}` | {item.get('status', 0)} | {signatures} | {secrets} | {endpoints} |")
    if len(interesting) > 100:
        lines.extend(["", f"其余 {len(interesting) - 100} 条请查看 `content-audit.jsonl`。"])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded web content leak validator and JS endpoint miner")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--limit", type=int, default=int(os.getenv("CONTENT_AUDIT_LIMIT", "500")))
    parser.add_argument("--workers", type=int, default=int(os.getenv("CONTENT_AUDIT_WORKERS", "10")))
    parser.add_argument("--timeout", type=int, default=int(os.getenv("CONTENT_AUDIT_TIMEOUT", "10")))
    parser.add_argument("--max-bytes", type=int, default=int(os.getenv("CONTENT_AUDIT_MAX_BYTES", "1048576")))
    parser.add_argument("--verify-tls", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    urls = load_urls(args.inputs, max(1, min(args.limit, 5000)))
    findings: list[dict[str, Any]] = []
    endpoints: set[str] = set()

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 50))) as pool:
        futures = {pool.submit(request_url, url, args.timeout, args.max_bytes, args.verify_tls): url for url in urls}
        for future in as_completed(futures):
            result = future.result()
            analyzed, found_endpoints = analyze(result)
            with LOCK:
                findings.append(analyzed)
                endpoints.update(found_endpoints)

    findings.sort(key=lambda item: (not bool(item.get("interesting")), str(item.get("url") or "")))
    (args.output_dir / "content-audit.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in findings), encoding="utf-8"
    )
    (args.output_dir / "content-endpoints.txt").write_text(
        "".join(f"{value}\n" for value in sorted(endpoints)), encoding="utf-8"
    )
    stats = {
        "requested": len(urls),
        "completed": len(findings),
        "http_success": sum(1 for item in findings if 200 <= int(item.get("status") or 0) < 400),
        "interesting": sum(1 for item in findings if item.get("interesting")),
        "leak_signatures": sum(len(item.get("leak_signatures") or []) for item in findings),
        "secret_indicators": sum(len(item.get("secret_indicators") or []) for item in findings),
        "endpoints": len(endpoints),
        "errors": sum(1 for item in findings if item.get("error")),
    }
    (args.output_dir / "content-audit-stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "content-findings.md").write_text(markdown(findings), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
