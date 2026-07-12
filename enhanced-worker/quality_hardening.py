#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reduce legacy WIH and file-leak false positives during image build.

The ARL file leak task historically consumes a broad directory/file wordlist.
Merging a complete RAFT list makes ordinary public files look like leakage.
This script keeps only paths that carry actionable credential, configuration,
backup, source-control, debug, log, database or API-document evidence.

WIH cloud-key validation is kept enabled by default. The legacy ``--dc`` flag
(disable cloud-key checking) is removed unless WIH_ALLOW_UNVERIFIED_KEYS=true
is explicitly supplied as a Docker build argument.

Compatible with Python 3.6 in the ARL worker image.
"""

from __future__ import print_function

import io
import os
import re
import sys


FILE_DICT = "/code/app/dicts/file_top_2000.txt"
INFO_HUNTER = "/code/app/services/infoHunter.py"
TRUE_VALUES = set(["1", "true", "yes", "on", "enabled"])

GENERIC_NOISE = set(
    [
        "admin",
        "administrator",
        "api",
        "api/v1",
        "api/v2",
        "api/v3",
        "assets/index.js",
        "assets/js/app.js",
        "assets/js/main.js",
        "backend",
        "callback",
        "callbacks",
        "console",
        "crossdomain.xml",
        "dev",
        "development",
        "docs",
        "download",
        "export",
        "health",
        "healthz",
        "hooks",
        "internal",
        "live",
        "livez",
        "manage",
        "management",
        "manifest.json",
        "metrics",
        "oauth/callback",
        "playground",
        "private",
        "prometheus",
        "ready",
        "readyz",
        "redoc",
        "rest",
        "robots.txt",
        "rpc",
        "sandbox",
        "security.txt",
        "service-worker.js",
        "sitemap.xml",
        "staging",
        "static/js/app.js",
        "static/js/main.js",
        "static/js/runtime.js",
        "status",
        "test",
        "testing",
        "uat",
        "upload",
        "uploads",
        ".well-known/assetlinks.json",
        ".well-known/jwks.json",
        ".well-known/openid-configuration",
        ".well-known/security.txt",
    ]
)

LOW_VALUE_BUILD_FILES = set(
    [
        ".dockerignore",
        ".gitattributes",
        ".gitignore",
        ".gitmodules",
        "cargo.lock",
        "cargo.toml",
        "chart.yaml",
        "composer.json",
        "composer.lock",
        "dockerfile",
        "dockerfile.dev",
        "dockerfile.prod",
        "gemfile",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "package.json",
        "pipfile",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "pom.xml",
        "requirements-dev.txt",
        "requirements.txt",
        "yarn.lock",
    ]
)

HIGH_SIGNAL_PREFIXES = (
    ".env",
    ".git/",
    ".hg/",
    ".svn/",
    ".aws/",
    ".idea/workspace.xml",
    ".npmrc",
    ".pypirc",
    ".netrc",
)

HIGH_SIGNAL_EXACT = set(
    [
        "actuator/beans",
        "actuator/configprops",
        "actuator/env",
        "actuator/heapdump",
        "actuator/loggers",
        "actuator/mappings",
        "actuator/threaddump",
        "api-docs",
        "api-docs.json",
        "api-docs.yaml",
        "azureprofile.json",
        "backend.tf",
        "credentials.json",
        "gcp-service-account.json",
        "graphiql",
        "graphql-playground",
        "id_ed25519",
        "id_rsa",
        "info.php",
        "phpinfo.php",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
        "server-info",
        "server-status",
        "service-account.json",
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
        "swagger-resources",
        "swagger-ui.html",
        "swagger-ui/index.html",
        "swagger/index.html",
        "terraform.tfstate",
        "terraform.tfstate.backup",
        "v1/api-docs",
        "v2/api-docs",
        "v3/api-docs",
        "web.config",
        "web.config.bak",
    ]
)

SENSITIVE_NAME_RE = re.compile(
    r"(^|[/_.-])(credential|credentials|secret|secrets|token|apikey|api-key|"
    r"private[-_]?key|service[-_]?account|keystore|truststore)([/_.-]|$)",
    re.I,
)
CONFIG_NAME_RE = re.compile(
    r"(^|/)(application|bootstrap|config|configuration|settings|local_settings|"
    r"appsettings|wp-config)([-_.A-Za-z0-9]*)(\.(ya?ml|json|properties|xml|php|py|inc))"
    r"(\.(bak|backup|old|save|orig|swp))?$",
    re.I,
)
ARCHIVE_RE = re.compile(
    r"(^|/)(backup|dump|database|db|mysql|postgres|site|www|wwwroot|web|source|src|"
    r"release|archive|old|bak|public|html|latest)([-_.A-Za-z0-9]*)"
    r"\.(zip|7z|rar|tar|tgz|tar\.gz|sql|sql\.gz|db|sqlite|sqlite3)$",
    re.I,
)
LOG_RE = re.compile(r"(^|/)([^/]*(error|access|debug|application|app|laravel|catalina)[^/]*)\.(log|out)$", re.I)
BACKUP_SUFFIX_RE = re.compile(r"\.(bak|backup|old|save|orig|swp|tmp|copy)$", re.I)
SOURCE_MAP_RE = re.compile(r"\.(js|css)\.map$", re.I)
PRIVATE_KEY_RE = re.compile(r"(^|/)(id_rsa|id_ed25519|[^/]*private[^/]*\.(key|pem)|[^/]*\.p12|[^/]*\.pfx)$", re.I)


def env_true(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return raw.strip().lower() in TRUE_VALUES


def read_text(path):
    with io.open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def write_text(path, content):
    temporary = path + ".quality.tmp"
    with io.open(temporary, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.replace(temporary, path)


def normalize_path(raw):
    value = (raw or "").strip().replace("\\", "/")
    value = value.split("?", 1)[0].split("#", 1)[0]
    while value.startswith("./"):
        value = value[2:]
    return value.lstrip("/").strip()


def is_high_signal_path(raw):
    value = normalize_path(raw)
    lowered = value.lower()
    if not value or value.startswith("#"):
        return False
    if lowered in GENERIC_NOISE or lowered in LOW_VALUE_BUILD_FILES:
        return False
    if lowered.startswith(HIGH_SIGNAL_PREFIXES):
        return True
    if lowered in HIGH_SIGNAL_EXACT:
        return True
    if SENSITIVE_NAME_RE.search(lowered):
        return True
    if CONFIG_NAME_RE.search(lowered):
        return True
    if ARCHIVE_RE.search(lowered):
        return True
    if LOG_RE.search(lowered):
        return True
    if PRIVATE_KEY_RE.search(lowered):
        return True
    if SOURCE_MAP_RE.search(lowered):
        return True
    if BACKUP_SUFFIX_RE.search(lowered):
        return True
    if lowered.startswith("web-inf/") or lowered.startswith("meta-inf/"):
        return True
    return False


def filter_file_dictionary():
    if not os.path.isfile(FILE_DICT):
        raise RuntimeError("required ARL file dictionary missing: {}".format(FILE_DICT))

    original = read_text(FILE_DICT).splitlines()
    kept = []
    seen = set()
    for raw in original:
        value = normalize_path(raw)
        if not is_high_signal_path(value):
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        kept.append(value)

    minimum = int(os.getenv("ARL_FILE_LEAK_MIN_DICTIONARY", "40"))
    if len(kept) < minimum:
        raise RuntimeError(
            "strict file-leak dictionary unexpectedly small: {} < {}".format(
                len(kept), minimum
            )
        )

    write_text(FILE_DICT, "\n".join(kept) + "\n")
    return len(original), len(kept)


def harden_info_hunter():
    if not os.path.isfile(INFO_HUNTER):
        print("[WARN] infoHunter.py missing; WIH hardening skipped")
        return "missing"

    content = read_text(INFO_HUNTER)
    allow_unverified = env_true("WIH_ALLOW_UNVERIFIED_KEYS", False)
    if allow_unverified:
        return "unverified-key-checks-explicitly-disabled"

    original = content
    content = re.sub(r"^[ \t]*[\"']--dc[\"'][ \t]*,[ \t]*\n", "", content, flags=re.M)
    content = content.replace('"-J",\n                   "-f",\n                   "--dc",', '"-J",\n                   "-f",')
    content = content.replace("'-J',\n                   '-f',\n                   '--dc',", "'-J',\n                   '-f',")

    if "--dc" in content:
        raise RuntimeError("WIH --dc flag remains after strict hardening")
    if content != original:
        write_text(INFO_HUNTER, content)
        return "cloud-key-validation-enabled"
    return "already-strict"


def main():
    before, after = filter_file_dictionary()
    wih_state = harden_info_hunter()
    print("[OK] strict file-leak dictionary: {} -> {} entries".format(before, after))
    print("[OK] WIH quality mode: {}".format(wih_state))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("[ERROR] quality hardening failed: {}".format(exc), file=sys.stderr)
        sys.exit(1)
