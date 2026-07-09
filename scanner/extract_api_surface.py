#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from asset_intelligence import normalize_url, sanitize_query_pairs

API_PATTERN = re.compile(
    r"/(?:api(?:/|$)|rest(?:/|$)|rpc(?:/|$)|graphql(?:/|$)|graphiql(?:/|$)|"
    r"openapi(?:/|$)|swagger(?:/|$)|v[0-9]+(?:/|$)|oauth(?:/|$)|auth(?:/|$)|"
    r"webhook(?:s)?(?:/|$)|callback(?:s)?(?:/|$)|notify(?:/|$)|hooks?(?:/|$))",
    re.I,
)
DOC_PATTERN = re.compile(
    r"(?:swagger|openapi|api-docs|v[23]/api-docs|redoc|graphiql|graphql-playground)",
    re.I,
)
WEBHOOK_PATTERN = re.compile(r"/(?:webhook(?:s)?|callback(?:s)?|notify|hooks?)(?:/|$)", re.I)
JS_PATTERN = re.compile(r"\.m?js(?:$|\?)", re.I)


def iter_values(paths: list[Path]):
    for path in paths:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = raw.strip()
            if value:
                yield value


def write_lines(path: Path, values: set[str]) -> None:
    path.write_text("".join(f"{value}\n" for value in sorted(values)), encoding="utf-8")


def normalize_websocket(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
            return None
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower().strip(".")
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((parsed.scheme == "ws" and port == 80) or (parsed.scheme == "wss" and port == 443)):
        netloc = f"{netloc}:{port}"
    query_pairs, _ = sanitize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", urlencode(sorted(query_pairs), doseq=True), ""))


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract API and callback call surfaces")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    api_endpoints: set[str] = set()
    api_docs: set[str] = set()
    webhooks: set[str] = set()
    websockets: set[str] = set()
    js_files: set[str] = set()
    invalid = 0
    redacted_query_values = 0

    for raw_value in iter_values(args.inputs):
        try:
            original = urlsplit(raw_value)
            _, changed = sanitize_query_pairs(parse_qsl(original.query, keep_blank_values=True))
            redacted_query_values += int(changed)
        except ValueError:
            changed = False

        if raw_value.startswith(("ws://", "wss://")):
            websocket = normalize_websocket(raw_value)
            if websocket:
                websockets.add(websocket)
            else:
                invalid += 1
            continue

        value = normalize_url(raw_value)
        if not value:
            invalid += 1
            continue
        try:
            parsed = urlsplit(value)
        except ValueError:
            invalid += 1
            continue
        path_and_query = parsed.path + (("?" + parsed.query) if parsed.query else "")
        if API_PATTERN.search(parsed.path):
            api_endpoints.add(value)
        if DOC_PATTERN.search(path_and_query):
            api_docs.add(value)
        if WEBHOOK_PATTERN.search(parsed.path):
            webhooks.add(value)
        if JS_PATTERN.search(path_and_query):
            js_files.add(value)

    write_lines(args.output_dir / "api-endpoints.txt", api_endpoints)
    write_lines(args.output_dir / "api-docs-endpoints.txt", api_docs)
    write_lines(args.output_dir / "webhook-endpoints.txt", webhooks)
    write_lines(args.output_dir / "websocket-endpoints.txt", websockets)
    write_lines(args.output_dir / "js-files.txt", js_files)

    stats = {
        "api_endpoints": len(api_endpoints),
        "api_docs": len(api_docs),
        "webhooks": len(webhooks),
        "websockets": len(websockets),
        "javascript_files": len(js_files),
        "invalid_lines": invalid,
        "redacted_query_values": redacted_query_values,
    }
    (args.output_dir / "api-surface-stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
