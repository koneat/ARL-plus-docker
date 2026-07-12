#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import ssl
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

USER_AGENT = "ARL-Plus-Scanner/2.1 authorized-security-assessment"

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def lines(path: Path) -> Iterable[str]:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = raw.strip()
        if value:
            yield value


def jsonl(path: Path) -> Iterable[dict[str, Any]]:
    for raw in lines(path):
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            yield item


def load(path: Path, default: Any) -> Any:
    if not path.is_file() or not path.stat().st_size:
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def dump_jsonl(path: Path, items: Iterable[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in items), encoding="utf-8")


def normalize_url(value: Any) -> str | None:
    raw = str(value or "").strip()
    try:
        p = urlsplit(raw)
        port = p.port
    except ValueError:
        return None
    if p.scheme.lower() not in {"http", "https"} or not p.hostname:
        return None
    scheme, host = p.scheme.lower(), p.hostname.lower().strip(".")
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc += f":{port}"
    path = re.sub(r"/{2,}", "/", p.path or "/")
    return urlunsplit((scheme, netloc, path, "", ""))


def origin(value: Any) -> str | None:
    url = normalize_url(value)
    if not url:
        return None
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def roots(path: Path | None) -> list[str]:
    return sorted({v.lower().strip(".") for v in lines(path)}) if path and path.is_file() else []


def scoped(host: str | None, scope: list[str]) -> bool:
    if not host:
        return False
    host = host.lower().strip(".")
    return not scope or any(host == root or host.endswith("." + root) for root in scope)


def fetch(url: str, timeout: int, max_bytes: int, verify_tls: bool) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ctx))
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, application/yaml, text/yaml, */*;q=0.2", "Connection": "close"})
    try:
        with opener.open(req, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                return {"url": url, "status": int(getattr(response, "status", 200)), "error": "too-large"}
            return {"url": url, "status": int(getattr(response, "status", 200)), "content_type": response.headers.get("Content-Type", "").split(";", 1)[0].lower(), "body": body}
    except HTTPError as exc:
        return {"url": url, "status": int(exc.code), "error": "http-error"}
    except (URLError, TimeoutError, ssl.SSLError, OSError, ValueError) as exc:
        return {"url": url, "status": 0, "error": type(exc).__name__}
