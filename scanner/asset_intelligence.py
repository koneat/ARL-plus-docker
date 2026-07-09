#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
SENSITIVE_VALUE_RE = re.compile(
    r"^(?:eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|(?:ghp|github_pat|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}|"
    r"AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[0-9A-Za-z-]{20,})$"
)
SENSITIVE_EXTENSIONS = {
    ".env", ".bak", ".old", ".save", ".sql", ".sqlite", ".db", ".log", ".map", ".yaml", ".yml",
    ".json", ".xml", ".ini", ".conf", ".config", ".properties", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
}
HIGH_KEYWORDS = {
    "admin", "administrator", "manage", "management", "console", "dashboard", "internal", "private", "debug",
    "actuator", "swagger", "openapi", "graphql", "graphiql", "api-docs", "upload", "import", "export",
    "download", "backup", "dump", "database", "config", "secret", "credential", "token", "auth", "oauth",
    "login", "signin", "signup", "reset", "password", "webhook", "callback", "notify", "payment", "order",
    "wallet", "withdraw", "transfer", "settlement", "report", "metrics", "prometheus", "trace", "logs",
}
API_HINTS = {"api", "rest", "rpc", "graphql", "webhook", "callback", "openapi", "swagger", "api-docs"}
SECRET_PARAM_HINTS = {"token", "key", "secret", "password", "passwd", "auth", "jwt", "session", "signature", "sign", "apikey", "api_key", "access_token", "refresh_token"}


def read_lines(paths: Iterable[Path]) -> Iterable[str]:
    for path in paths:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = raw.strip()
            if value:
                yield value


def roots_from(path: Path) -> list[str]:
    roots: list[str] = []
    for value in read_lines([path]):
        host = value.lower().strip(".")
        if HOST_RE.match(host):
            roots.append(host)
    return sorted(set(roots))


def in_scope(host: str, roots: list[str]) -> bool:
    host = host.lower().strip(".")
    return any(host == root or host.endswith("." + root) for root in roots)


def normalize_host(value: str) -> str | None:
    candidate = value.strip().lower().strip(".")
    if not candidate:
        return None
    if "://" in candidate:
        try:
            candidate = urlsplit(candidate).hostname or ""
        except ValueError:
            return None
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if ":" in candidate and not HOST_RE.match(candidate):
        try:
            ipaddress.ip_address(candidate)
            return None
        except ValueError:
            if candidate.count(":") == 1:
                candidate = candidate.rsplit(":", 1)[0]
    if HOST_RE.match(candidate):
        return candidate
    return None


def sanitize_query_pairs(pairs: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], bool]:
    sanitized: list[tuple[str, str]] = []
    changed = False
    for name, value in pairs:
        normalized_name = name.lower().replace("-", "_")
        sensitive_name = normalized_name in SECRET_PARAM_HINTS or any(
            hint in normalized_name for hint in ("token", "secret", "password", "passwd", "signature", "credential")
        )
        sensitive_value = bool(SENSITIVE_VALUE_RE.match(value))
        if sensitive_name or sensitive_value:
            sanitized.append((name, ""))
            changed = changed or bool(value)
        else:
            sanitized.append((name, value))
    return sanitized, changed


def normalize_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower().strip(".")
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = host
    if ":" in host:
        netloc = f"[{host}]"
    if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    query_pairs, _ = sanitize_query_pairs(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(sorted(query_pairs), doseq=True)
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))


def url_score(url: str) -> tuple[int, list[str]]:
    parsed = urlsplit(url)
    path_lower = parsed.path.lower()
    tokens = {token for token in re.split(r"[^a-z0-9]+", path_lower) if token}
    score = 0
    reasons: list[str] = []
    matched_keywords = sorted(tokens & HIGH_KEYWORDS)
    if matched_keywords:
        score += min(8, 2 + len(matched_keywords))
        reasons.append("keyword:" + ",".join(matched_keywords[:5]))
    suffixes = Path(path_lower).suffixes
    extension = "".join(suffixes[-2:]) if len(suffixes) >= 2 and suffixes[-2:] == [".tar", ".gz"] else (suffixes[-1] if suffixes else "")
    if extension in SENSITIVE_EXTENSIONS or path_lower.endswith(".tar.gz"):
        score += 5
        reasons.append("sensitive-extension")
    if parsed.query:
        score += 2
        reasons.append("parameters")
        parameter_names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        if parameter_names & SECRET_PARAM_HINTS or any(
            any(hint in name for hint in ("token", "secret", "password", "signature")) for name in parameter_names
        ):
            score += 2
            reasons.append("sensitive-parameter")
    if tokens & API_HINTS:
        score += 3
        reasons.append("api")
    if path_lower.endswith((".js", ".mjs")):
        score += 1
        reasons.append("javascript")
    depth = len([part for part in parsed.path.split("/") if part])
    if depth >= 4:
        score += 1
        reasons.append("deep-path")
    return score, reasons


def cmd_domains(args: argparse.Namespace) -> int:
    roots = roots_from(args.roots)
    accepted: set[str] = set()
    rejected: set[str] = set()
    for raw in read_lines(args.inputs):
        host = normalize_host(raw)
        if not host:
            continue
        if in_scope(host, roots):
            accepted.add(host)
        else:
            rejected.add(host)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(f"{value}\n" for value in sorted(accepted)), encoding="utf-8")
    if args.rejected:
        args.rejected.write_text("".join(f"{value}\n" for value in sorted(rejected)), encoding="utf-8")
    return 0


def cmd_urls(args: argparse.Namespace) -> int:
    roots = roots_from(args.roots)
    accepted: dict[str, dict[str, object]] = {}
    rejected = 0
    invalid = 0
    redacted_query_values = 0
    for raw in read_lines(args.inputs):
        try:
            original = urlsplit(raw)
            _, changed = sanitize_query_pairs(parse_qsl(original.query, keep_blank_values=True))
            redacted_query_values += int(changed)
        except ValueError:
            pass
        url = normalize_url(raw)
        if not url:
            invalid += 1
            continue
        host = urlsplit(url).hostname or ""
        if not in_scope(host, roots):
            rejected += 1
            continue
        score, reasons = url_score(url)
        current = accepted.get(url)
        if current is None or int(current["score"]) < score:
            accepted[url] = {"url": url, "score": score, "reasons": reasons}

    ordered = sorted(accepted.values(), key=lambda item: (-int(item["score"]), str(item["url"])))
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)

    all_urls = [str(item["url"]) for item in ordered]
    priority = [str(item["url"]) for item in ordered if int(item["score"]) >= args.priority_score]
    api_urls = [str(item["url"]) for item in ordered if "api" in item["reasons"]]
    param_urls = [str(item["url"]) for item in ordered if "parameters" in item["reasons"]]
    sensitive = [str(item["url"]) for item in ordered if "sensitive-extension" in item["reasons"] or "sensitive-parameter" in item["reasons"]]
    javascript = [str(item["url"]) for item in ordered if "javascript" in item["reasons"]]
    origins = sorted({f"{urlsplit(url).scheme}://{urlsplit(url).netloc}" for url in all_urls})

    outputs = {
        "urls-intelligence-all.txt": all_urls,
        "urls-priority.txt": priority,
        "urls-api.txt": api_urls,
        "urls-params.txt": param_urls,
        "urls-sensitive.txt": sensitive,
        "urls-js.txt": javascript,
        "origins.txt": origins,
    }
    for name, values in outputs.items():
        (out / name).write_text("".join(f"{value}\n" for value in values), encoding="utf-8")
    (out / "url-intelligence.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in ordered), encoding="utf-8"
    )
    scores = Counter(str(item["score"]) for item in ordered)
    stats = {
        "accepted": len(ordered),
        "priority": len(priority),
        "api": len(api_urls),
        "parameterized": len(param_urls),
        "sensitive": len(sensitive),
        "javascript": len(javascript),
        "origins": len(origins),
        "rejected_out_of_scope": rejected,
        "invalid": invalid,
        "redacted_query_values": redacted_query_values,
        "score_distribution": dict(sorted(scores.items(), key=lambda item: int(item[0]))),
    }
    (out / "url-intelligence-stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


def cmd_tlsx(args: argparse.Namespace) -> int:
    roots = roots_from(args.roots)
    sans: set[str] = set()
    findings: list[dict[str, object]] = []
    invalid = 0
    for raw in read_lines([args.input]):
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if not isinstance(item, dict):
            continue
        values: list[str] = []
        for key in ("subject_an", "subject_an_dns", "san", "dns_names"):
            value = item.get(key)
            if isinstance(value, list):
                values.extend(str(entry) for entry in value)
            elif value:
                values.append(str(value))
        for value in values:
            host = normalize_host(value)
            if host and in_scope(host, roots):
                sans.add(host)
        flags = {
            name: bool(item.get(name) or item.get(name.replace("_", "-")))
            for name in ("expired", "self_signed", "mismatched", "revoked", "untrusted", "wildcard_cert")
        }
        if any(flags.values()):
            findings.append({
                "host": item.get("host") or item.get("input") or item.get("ip"),
                "port": item.get("port"),
                "tls_version": item.get("tls_version") or item.get("version"),
                "cipher": item.get("cipher"),
                "flags": flags,
            })
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "tls-san-domains.txt").write_text("".join(f"{value}\n" for value in sorted(sans)), encoding="utf-8")
    (args.output_dir / "tls-findings.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in findings), encoding="utf-8"
    )
    (args.output_dir / "tls-stats.json").write_text(
        json.dumps({"san_domains": len(sans), "misconfigurations": len(findings), "invalid": invalid}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scope-aware scanner asset intelligence")
    sub = parser.add_subparsers(dest="command", required=True)

    domains = sub.add_parser("domains")
    domains.add_argument("roots", type=Path)
    domains.add_argument("output", type=Path)
    domains.add_argument("inputs", nargs="+", type=Path)
    domains.add_argument("--rejected", type=Path)
    domains.set_defaults(func=cmd_domains)

    urls = sub.add_parser("urls")
    urls.add_argument("roots", type=Path)
    urls.add_argument("output_dir", type=Path)
    urls.add_argument("inputs", nargs="+", type=Path)
    urls.add_argument("--priority-score", type=int, default=4)
    urls.set_defaults(func=cmd_urls)

    tlsx = sub.add_parser("tlsx")
    tlsx.add_argument("roots", type=Path)
    tlsx.add_argument("input", type=Path)
    tlsx.add_argument("output_dir", type=Path)
    tlsx.set_defaults(func=cmd_tlsx)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
