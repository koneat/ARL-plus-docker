#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ALLOWED_KEYS = (
    "SCANNER_V2_WORKERS",
    "SCANNER_V2_MAX_QUEUE",
    "SCANNER_V2_TIMEOUT",
    "SCAN_MODE",
    "UPDATE_TEMPLATES",
    "NUCLEI_TEMPLATE_UPDATE_TIMEOUT",
    "ENABLE_SCANNER_V2",
    "ENABLE_SUBFINDER",
    "ENABLE_UNCOVER",
    "ENABLE_NAABU",
    "ENABLE_KATANA",
    "ENABLE_SOURCEMAP",
    "ENABLE_PASSIVE_URLS",
    "ENABLE_TLSX",
    "ENABLE_CDNCHECK",
    "ENABLE_ALTERX",
    "ENABLE_SECONDARY_CRAWL",
    "ENABLE_SOURCEMAP_V2",
    "ENABLE_FFUF_V2",
    "ENABLE_CONTENT_AUDIT",
    "ENABLE_EDGE_INTELLIGENCE",
    "ENABLE_API_SCHEMA_INTELLIGENCE",
    "ENABLE_ACTIONABLE_INTELLIGENCE",
    "ENABLE_SCAN_DELTA",
    "ENABLE_NUCLEI",
    "ENABLE_NUCLEI_AUTOMATIC",
    "ENABLE_NUCLEI_EXPOSURE",
    "ENABLE_NUCLEI_API",
    "ENABLE_NUCLEI_NETWORK",
    "ENABLE_NUCLEI_DNS",
    "ENABLE_AFROG",
    "ENABLE_FFUF",
    "UNCOVER_ENGINES",
    "UNCOVER_LIMIT",
    "UNCOVER_RATE_LIMIT",
    "UNCOVER_ACCEPT_IP_ONLY",
    "NUCLEI_POLICY",
    "NUCLEI_TEMPLATE_MIN_COUNT",
    "NUCLEI_EXCLUDE_TAGS",
    "NUCLEI_RATE_LIMIT",
    "NUCLEI_TIMEOUT",
    "CUSTOM_PORTS",
    "TOP_PORTS_OVERRIDE",
    "NAABU_SERVICE_VERSION_OVERRIDE",
    "SCAN_URL_LIMIT_OVERRIDE",
    "NUCLEI_SEVERITY_OVERRIDE",
    "AFROG_SEVERITY_OVERRIDE",
)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: persist-scanner-compose-env.py COMPOSE_ENV ENV_TOOL")
    compose_env = Path(sys.argv[1]).resolve()
    env_tool = Path(sys.argv[2]).resolve()
    if not compose_env.is_file():
        raise SystemExit(f"compose env missing: {compose_env}")
    if not env_tool.is_file():
        raise SystemExit(f"compose env tool missing: {env_tool}")

    for key in ALLOWED_KEYS:
        if key not in os.environ:
            continue
        subprocess.run(
            [sys.executable, str(env_tool), str(compose_env), "set", key, os.environ[key]],
            check=True,
        )


if __name__ == "__main__":
    main()
