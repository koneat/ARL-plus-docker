#!/usr/bin/env python3
from __future__ import annotations

"""Compatibility entrypoint that hardens edge_intelligence scope handling.

The implementation stays in edge_intelligence.py. This entrypoint replaces the
few boundary-sensitive helpers before invoking its CLI so upgrades remain easy
to review and regression-test.
"""

import ipaddress
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

import edge_intelligence as base
from intelligence_common import lines


def host_of(value: Any) -> str:
    raw = str(value or "").strip().lower().strip(".")
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw if "://" in raw else "//" + raw)
        host = (parsed.hostname or "").lower().strip(".")
    except ValueError:
        return ""
    return host.strip("[]")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def scope(root: Path) -> tuple[list[str], set[str]]:
    domains: set[str] = set()
    ips: set[str] = set()
    primary = root / "domains.txt"
    domain_files = (primary,) if primary.is_file() and primary.stat().st_size else (root / "domains.all.txt",)
    for path in domain_files:
        for value in lines(path):
            host = host_of(value.replace("*.", ""))
            if host:
                (ips if is_ip(host) else domains).add(host)
    for value in lines(root / "ips.txt"):
        host = host_of(value)
        if is_ip(host):
            ips.add(host)
    return sorted(domains), ips


def github_collect(domains: list[str], token: str, max_queries: int, max_files: int,
                   timeout: int, max_bytes: int):
    if not token or not domains:
        return [], ["github-skipped:no-token-or-domain"]
    headers = {
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    suffixes = ("", " path:.github/workflows", " staging", " dev", " uat", " preprod")
    queries = [f'"{root}"{suffix}' for suffix in suffixes for root in domains[:10]]
    files: dict[tuple[str, str, str], dict[str, Any]] = {}
    errors: list[str] = []
    for query in list(dict.fromkeys(queries))[:max_queries]:
        if len(files) >= max_files:
            break
        url = "https://api.github.com/search/code?" + urlencode({
            "q": query,
            "per_page": min(30, max_files),
            "page": 1,
        })
        try:
            payload = base.request_json(url, headers, timeout, max_bytes)
        except HTTPError as exc:
            errors.append(f"github-search:http-{exc.code}")
            if exc.code in {401, 403, 422}:
                break
            continue
        except Exception as exc:
            errors.append("github-search:" + type(exc).__name__)
            continue
        for item in payload.get("items", []) if isinstance(payload, dict) else []:
            repo = str((item.get("repository") or {}).get("full_name") or "")
            path = str(item.get("path") or "")
            api_url = str(item.get("url") or "")
            sha = str(item.get("sha") or "")
            if not repo or not path or not api_url:
                continue
            key = (repo, path, sha)
            if key in files:
                files[key]["queries"].append(query)
            elif len(files) < max_files:
                files[key] = {
                    "repository": repo,
                    "path": path,
                    "sha": sha,
                    "api_url": api_url,
                    "html_url": item.get("html_url"),
                    "queries": [query],
                }
    output = []
    for item in files.values():
        try:
            req = Request(item["api_url"], headers={
                "User-Agent": base.USER_AGENT,
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Accept": "application/vnd.github.raw+json",
            })
            with urlopen(req, timeout=timeout) as response:
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    item["fetch_error"] = "file-too-large"
                else:
                    item["content"] = data.decode("utf-8", errors="replace")
        except HTTPError as exc:
            item["fetch_error"] = f"http-{exc.code}"
        except Exception as exc:
            item["fetch_error"] = type(exc).__name__
        output.append(item)
    return output, errors


base.host_of = host_of
base.is_ip = is_ip
base.scope = scope
base.github_collect = github_collect


if __name__ == "__main__":
    args = base.parser().parse_args()
    raise SystemExit(args.func(args))
