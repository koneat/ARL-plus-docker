#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from asset_intelligence import normalize_url, sanitize_query_pairs

TEXT_URL_FILES = (
    "uncover-urls.txt",
    "urlfinder.txt",
    "gau.txt",
    "passive-urls.raw.txt",
    "passive-probe-targets.txt",
    "passive-live-urls.txt",
    "enriched-live-urls.txt",
    "live-urls.txt",
    "katana.txt",
    "katana.enriched.txt",
    "sourcemap-candidates.txt",
    "sourcemap-v2-candidates.txt",
    "sourcemaps.v2.urls.txt",
    "ffuf-v2-hits.txt",
    "urls-intelligence-all.txt",
    "urls-priority.txt",
    "urls-api.txt",
    "urls-params.txt",
    "urls-sensitive.txt",
    "urls-js.txt",
    "origins.txt",
    "content-endpoints.txt",
    "scan-urls.all.txt",
    "scan-urls.txt",
    "api-endpoints.txt",
    "api-docs-endpoints.txt",
    "webhook-endpoints.txt",
    "websocket-endpoints.txt",
    "js-files.txt",
)

JSONL_FILES = (
    "uncover.jsonl",
    "uncover.scoped.jsonl",
    "uncover.candidates.jsonl",
    "urlfinder.jsonl",
    "httpx.jsonl",
    "passive-httpx.jsonl",
    "enriched-httpx.jsonl",
    "content-audit.jsonl",
    "url-intelligence.jsonl",
    "sourcemaps.jsonl",
    "sourcemaps.v2.jsonl",
)

URL_KEYS = {
    "url", "input", "location", "redirect_location", "matched-at", "matched_at", "host",
    "request-url", "request_url", "endpoint", "target",
}


def sanitize_websocket(value: str) -> tuple[str, bool]:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
            return value, False
        port = parsed.port
    except ValueError:
        return value, False
    host = parsed.hostname.lower().strip(".")
    netloc = f"[{host}]" if ":" in host else host
    if port and not ((parsed.scheme == "ws" and port == 80) or (parsed.scheme == "wss" and port == 443)):
        netloc = f"{netloc}:{port}"
    pairs, changed = sanitize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", urlencode(sorted(pairs), doseq=True), "")), changed


def sanitize_relative(value: str) -> tuple[str, bool]:
    if not value.startswith(("/", "?")):
        return value, False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value, False
    pairs, changed = sanitize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(sorted(pairs), doseq=True), "")), changed


def sanitize_string(value: str) -> tuple[str, bool]:
    stripped = value.strip()
    if stripped.startswith(("http://", "https://")):
        try:
            parsed = urlsplit(stripped)
            _, changed = sanitize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))
        except ValueError:
            return value, False
        normalized = normalize_url(stripped)
        return (normalized if normalized is not None else value), changed
    if stripped.startswith(("ws://", "wss://")):
        return sanitize_websocket(stripped)
    return sanitize_relative(value)


def sanitize_text_file(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {"lines": 0, "changed": 0, "invalid": 0}
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    output: list[str] = []
    seen: set[str] = set()
    changed_count = 0
    invalid = 0
    for raw in lines:
        value = raw.strip()
        if not value:
            continue
        sanitized, changed = sanitize_string(value)
        if value.startswith(("http://", "https://")) and not sanitized.startswith(("http://", "https://")):
            invalid += 1
            continue
        changed_count += int(changed or sanitized != value)
        if sanitized not in seen:
            seen.add(sanitized)
            output.append(sanitized)
    path.write_text("".join(f"{value}\n" for value in output), encoding="utf-8")
    return {"lines": len(output), "changed": changed_count, "invalid": invalid}


def sanitize_json_value(value: Any, key: str | None = None) -> tuple[Any, int]:
    changed = 0
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for child_key, child_value in value.items():
            sanitized, count = sanitize_json_value(child_value, str(child_key))
            result[str(child_key)] = sanitized
            changed += count
        return result, changed
    if isinstance(value, list):
        result_list: list[Any] = []
        for child in value:
            sanitized, count = sanitize_json_value(child, key)
            result_list.append(sanitized)
            changed += count
        return result_list, changed
    if isinstance(value, str) and (key in URL_KEYS or value.startswith(("http://", "https://", "ws://", "wss://"))):
        sanitized, was_changed = sanitize_string(value)
        return sanitized, int(was_changed or sanitized != value)
    return value, 0


def sanitize_jsonl_file(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {"records": 0, "changed": 0, "invalid": 0}
    records: list[str] = []
    changed_count = 0
    invalid = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            invalid += 1
            continue
        sanitized, count = sanitize_json_value(item)
        changed_count += count
        records.append(json.dumps(sanitized, ensure_ascii=False))
    path.write_text("".join(record + "\n" for record in records), encoding="utf-8")
    return {"records": len(records), "changed": changed_count, "invalid": invalid}


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact sensitive query values from scanner result artifacts")
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()

    root = args.result_dir
    root.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"text": {}, "jsonl": {}, "total_changed": 0, "total_invalid": 0}

    for name in TEXT_URL_FILES:
        stats = sanitize_text_file(root / name)
        if stats["lines"] or stats["changed"] or stats["invalid"]:
            report["text"][name] = stats
        report["total_changed"] += stats["changed"]
        report["total_invalid"] += stats["invalid"]

    for name in JSONL_FILES:
        stats = sanitize_jsonl_file(root / name)
        if stats["records"] or stats["changed"] or stats["invalid"]:
            report["jsonl"][name] = stats
        report["total_changed"] += stats["changed"]
        report["total_invalid"] += stats["invalid"]

    (root / "artifact-sanitize-stats.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
