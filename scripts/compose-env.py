#!/usr/bin/env python3
"""Safely read and update simple KEY=VALUE entries in a Compose .env file."""

from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path

KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("env_file")
    sub = parser.add_subparsers(dest="action", required=True)

    for action in ("get", "has", "unset"):
        command = sub.add_parser(action)
        command.add_argument("key")

    command = sub.add_parser("set")
    command.add_argument("key")
    command.add_argument("value")
    return parser.parse_args()


def validate_key(key: str) -> None:
    if not KEY_RE.fullmatch(key):
        raise SystemExit(f"invalid environment key: {key!r}")


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def locate(lines: list[str], key: str) -> list[int]:
    pattern = re.compile(rf"^[ \t]*(?:export[ \t]+)?{re.escape(key)}=")
    return [index for index, line in enumerate(lines) if pattern.match(line)]


def value_of(line: str) -> str:
    value = line.split("=", 1)[1].rstrip("\r\n")
    return value


def atomic_write(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main() -> int:
    args = parse_args()
    validate_key(args.key)
    path = Path(args.env_file)
    lines = load_lines(path)
    matches = locate(lines, args.key)

    if args.action == "has":
        return 0 if matches else 1

    if args.action == "get":
        if not matches:
            return 1
        print(value_of(lines[matches[-1]]))
        return 0

    if args.action == "unset":
        if matches:
            match_set = set(matches)
            atomic_write(path, [line for index, line in enumerate(lines) if index not in match_set])
        return 0

    assert args.action == "set"
    replacement = f"{args.key}={args.value}\n"
    if matches:
        first = matches[0]
        lines[first] = replacement
        duplicate_set = set(matches[1:])
        lines = [line for index, line in enumerate(lines) if index not in duplicate_set]
    else:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += "\n"
        lines.append(replacement)
    atomic_write(path, lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
