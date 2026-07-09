#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{2,59})$"
)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} 必须是正整数") from exc
    if value < 1:
        raise SystemExit(f"{name} 必须是正整数")
    return value


def unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def normalize_hostname(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    if not value:
        return None
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return ascii_value if HOST_RE.fullmatch(ascii_value) else None


def split_host_port(value: str) -> tuple[str, int | None] | None:
    value = value.strip()
    if not value:
        return None

    if value.startswith("["):
        closing = value.find("]")
        if closing < 0:
            return None
        host = value[1:closing]
        suffix = value[closing + 1 :]
        if not suffix:
            return host, None
        if not suffix.startswith(":") or not suffix[1:].isdigit():
            return None
        port = int(suffix[1:])
        return (host, port) if 1 <= port <= 65535 else None

    if value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        if raw_port.isdigit():
            port = int(raw_port)
            return (host, port) if host and 1 <= port <= 65535 else None

    return value, None


def normalize_url(value: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None

    host = parsed.hostname.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
        host = str(address)
        host_for_netloc = f"[{host}]" if address.version == 6 else host
    except ValueError:
        normalized_host = normalize_hostname(host)
        if not normalized_host:
            return None
        host = normalized_host
        host_for_netloc = host

    try:
        parsed_port = parsed.port
    except ValueError:
        return None
    port = f":{parsed_port}" if parsed_port else ""

    netloc = f"{host_for_netloc}{port}"
    normalized = urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized, host


def classify(value: str) -> tuple[str, str] | None:
    value = value.strip()
    if not value or value.startswith("#"):
        return None

    if value.startswith("*."):
        value = value[2:]

    if "://" in value:
        normalized = normalize_url(value)
        if not normalized:
            return None
        url, host = normalized
        return "url", f"{url}\t{host}"

    candidate = value.rstrip(".")
    try:
        if "/" in candidate:
            return "cidr", str(ipaddress.ip_network(candidate, strict=False))
        return "ip", str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    split = split_host_port(candidate)
    if split is None:
        return None
    raw_host, port = split

    try:
        address = ipaddress.ip_address(raw_host)
    except ValueError:
        address = None
    if address is not None:
        host = str(address)
        if port is None:
            return "ip", host
        probe = f"[{host}]:{port}" if address.version == 6 else f"{host}:{port}"
        return "ip-port", f"{host}\t{probe}"

    host = normalize_hostname(raw_host)
    if not host:
        return None
    probe = f"{host}:{port}" if port is not None else host
    return "domain", f"{host}\t{probe}"


def write_lines(path: Path, values: list[str]) -> None:
    path.write_text("".join(f"{item}\n" for item in unique(values)), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"目标文件不存在: {args.input}")

    allow_large_cidr = env_bool("ALLOW_LARGE_CIDR", False)
    max_ipv4_addresses = env_positive_int("MAX_IPV4_CIDR_ADDRESSES", 4096)
    max_ipv6_addresses = env_positive_int("MAX_IPV6_CIDR_ADDRESSES", 256)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    raw_targets: list[str] = []
    hosts: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    cidrs: list[str] = []
    urls: list[str] = []
    http_probes: list[str] = []
    rejected: list[str] = []

    for raw in args.input.read_text(encoding="utf-8", errors="ignore").splitlines():
        result = classify(raw)
        if result is None:
            if raw.strip() and not raw.lstrip().startswith("#"):
                rejected.append(raw.strip())
            continue

        kind, normalized = result
        if kind == "url":
            url, host = normalized.split("\t", 1)
            urls.append(url)
            http_probes.append(url)
            hosts.append(host)
            raw_targets.append(url)
            try:
                ipaddress.ip_address(host)
                ips.append(host)
            except ValueError:
                domains.append(host)
        elif kind == "domain":
            host, probe = normalized.split("\t", 1)
            hosts.append(host)
            domains.append(host)
            http_probes.append(probe)
            raw_targets.append(probe)
        elif kind == "ip-port":
            host, probe = normalized.split("\t", 1)
            hosts.append(host)
            ips.append(host)
            http_probes.append(probe)
            raw_targets.append(probe)
        elif kind == "ip":
            hosts.append(normalized)
            ips.append(normalized)
            http_probes.append(normalized)
            raw_targets.append(normalized)
        else:
            network = ipaddress.ip_network(normalized, strict=False)
            limit = max_ipv4_addresses if network.version == 4 else max_ipv6_addresses
            if not allow_large_cidr and network.num_addresses > limit:
                rejected.append(
                    f"{raw.strip()}\tCIDR过大:{network.num_addresses}>允许值{limit};"
                    "设置ALLOW_LARGE_CIDR=true后才会扫描"
                )
                continue
            hosts.append(normalized)
            cidrs.append(normalized)
            raw_targets.append(normalized)

    write_lines(args.output_dir / "targets.normalized.txt", raw_targets)
    write_lines(args.output_dir / "hosts.txt", hosts)
    write_lines(args.output_dir / "domains.txt", domains)
    write_lines(args.output_dir / "ips.txt", ips)
    write_lines(args.output_dir / "cidrs.txt", cidrs)
    write_lines(args.output_dir / "urls.seed.txt", urls)
    write_lines(args.output_dir / "http-probe.txt", http_probes)
    write_lines(args.output_dir / "rejected.txt", rejected)

    counts = {
        "normalized": len(unique(raw_targets)),
        "hosts": len(unique(hosts)),
        "domains": len(unique(domains)),
        "ips": len(unique(ips)),
        "cidrs": len(unique(cidrs)),
        "seed_urls": len(unique(urls)),
        "http_probes": len(unique(http_probes)),
        "rejected": len(unique(rejected)),
    }
    (args.output_dir / "target-counts.json").write_text(
        json.dumps(counts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    if not raw_targets:
        raise SystemExit("没有可用目标。支持域名、IP、CIDR、host:port 和 HTTP(S) URL。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
