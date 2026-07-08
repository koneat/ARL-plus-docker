#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


def load_domains(path: Path) -> list[str]:
    values: set[str] = set()
    if not path.is_file():
        return []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = raw.strip().lower().strip(".")
        if value:
            values.add(value)
    return sorted(values)


def host_in_scope(host: str, domains: list[str]) -> bool:
    value = (host or "").lower().strip().strip(".")
    if not value:
        return False
    return any(value == domain or value.endswith("." + domain) for domain in domains)


def prepare_queries(domains_file: Path, output: Path, expanded: bool) -> None:
    queries: set[str] = set()
    for domain in load_domains(domains_file):
        queries.add(domain)
        if expanded:
            queries.add(f'ssl:"{domain}"')
    output.write_text("".join(f"{item}\n" for item in sorted(queries)), encoding="utf-8")


def valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return ""


def format_service(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def merge_results(
    jsonl_file: Path,
    domains_file: Path,
    output_dir: Path,
    accept_ip_only: bool,
) -> None:
    domains = load_domains(domains_file)
    output_dir.mkdir(parents=True, exist_ok=True)

    scoped_records: list[dict] = []
    candidate_records: list[dict] = []
    hosts: set[str] = set()
    services: set[str] = set()
    urls: set[str] = set()
    ip_candidates: set[str] = set()
    sources: Counter[str] = Counter()
    total = 0
    invalid = 0

    if jsonl_file.is_file():
        for raw in jsonl_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw.strip():
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                invalid += 1
                continue
            if not isinstance(item, dict):
                invalid += 1
                continue

            total += 1
            source = str(item.get("source") or "unknown").lower()
            sources[source] += 1
            host = str(item.get("host") or "").lower().strip().strip(".")
            ip = valid_ip(str(item.get("ip") or ""))
            url = str(item.get("url") or "").strip()
            try:
                port = int(item.get("port") or 0)
            except (TypeError, ValueError):
                port = 0

            url_host = ""
            if url:
                try:
                    parsed = urlsplit(url)
                    if parsed.scheme in {"http", "https"}:
                        url_host = (parsed.hostname or "").lower().strip(".")
                    else:
                        url = ""
                except ValueError:
                    url = ""

            scoped_host = host if host_in_scope(host, domains) else ""
            scoped_url_host = url_host if host_in_scope(url_host, domains) else ""
            is_scoped = bool(scoped_host or scoped_url_host)

            normalized = {
                "timestamp": item.get("timestamp"),
                "source": source,
                "host": host,
                "ip": ip,
                "port": port,
                "url": url,
                "in_scope": is_scoped,
            }

            if is_scoped:
                scoped_records.append(normalized)
                selected_host = scoped_host or scoped_url_host
                if selected_host:
                    hosts.add(selected_host)
                if url and scoped_url_host:
                    urls.add(url)
                if selected_host and 0 < port <= 65535:
                    services.add(format_service(selected_host, port))
                if ip:
                    ip_candidates.add(ip)
                continue

            if ip:
                ip_candidates.add(ip)
                if accept_ip_only and 0 < port <= 65535:
                    services.add(format_service(ip, port))
                    normalized["accepted_ip_only"] = True
                    scoped_records.append(normalized)
                    continue

            candidate_records.append(normalized)

    def write_lines(name: str, values: set[str]) -> None:
        (output_dir / name).write_text(
            "".join(f"{value}\n" for value in sorted(values)), encoding="utf-8"
        )

    def write_jsonl(name: str, values: list[dict]) -> None:
        (output_dir / name).write_text(
            "".join(json.dumps(value, ensure_ascii=False) + "\n" for value in values),
            encoding="utf-8",
        )

    write_lines("uncover-hosts.txt", hosts)
    write_lines("uncover-services.txt", services)
    write_lines("uncover-urls.txt", urls)
    write_lines("uncover-ip-candidates.txt", ip_candidates)
    write_jsonl("uncover.scoped.jsonl", scoped_records)
    write_jsonl("uncover.candidates.jsonl", candidate_records)

    stats = {
        "total_results": total,
        "invalid_lines": invalid,
        "scoped_results": len(scoped_records),
        "candidate_results": len(candidate_records),
        "scoped_hosts": len(hosts),
        "services": len(services),
        "urls": len(urls),
        "ip_candidates": len(ip_candidates),
        "accept_ip_only": accept_ip_only,
        "sources": dict(sorted(sources.items())),
    }
    (output_dir / "uncover-stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare and scope Uncover assets")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("domains_file", type=Path)
    prepare.add_argument("output", type=Path)
    prepare.add_argument("--expanded", action="store_true")

    merge = subparsers.add_parser("merge")
    merge.add_argument("jsonl_file", type=Path)
    merge.add_argument("domains_file", type=Path)
    merge.add_argument("output_dir", type=Path)
    merge.add_argument("--accept-ip-only", action="store_true")

    args = parser.parse_args()
    if args.command == "prepare":
        prepare_queries(args.domains_file, args.output, args.expanded)
    else:
        merge_results(
            args.jsonl_file,
            args.domains_file,
            args.output_dir,
            args.accept_ip_only,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
