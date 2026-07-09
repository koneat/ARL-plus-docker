#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from asset_intelligence import normalize_url, sanitize_query_pairs


def sanitize_file(source: Path, output: Path, stats_path: Path | None = None) -> dict[str, int]:
    raw_lines = source.read_text(encoding="utf-8", errors="ignore").splitlines() if source.is_file() else []
    seen: set[str] = set()
    ordered: list[str] = []
    invalid = 0
    redacted = 0

    for raw in raw_lines:
        value = raw.strip()
        if not value:
            continue
        try:
            parsed = urlsplit(value)
            _, changed = sanitize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))
            redacted += int(changed)
        except ValueError:
            pass

        normalized = normalize_url(value)
        if not normalized:
            invalid += 1
            continue
        if normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(f"{value}\n" for value in ordered), encoding="utf-8")
    stats = {
        "input": sum(1 for line in raw_lines if line.strip()),
        "output": len(ordered),
        "invalid": invalid,
        "redacted_query_values": redacted,
    }
    if stats_path is not None:
        stats_path.parent.mkdir(parents=True, exist_ok=True)
        stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize, redact and deduplicate active HTTP URL targets")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--stats", type=Path)
    args = parser.parse_args()
    sanitize_file(args.source, args.output, args.stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
