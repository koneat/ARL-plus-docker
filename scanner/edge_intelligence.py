#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

from intelligence_common import dump_jsonl, lines, normalize_url

USER_AGENT = "ARL-Plus-Edge-Intelligence/2026.07 authorized-passive-recon"
ENV_WORDS = ("dev", "development", "test", "testing", "qa", "uat", "stage", "staging",
             "preprod", "preview", "sandbox", "demo", "internal", "intranet",
             "backoffice", "canary", "local")
ENV_RE = re.compile(r"(?<![a-z0-9])(" + "|".join(sorted(ENV_WORDS, key=len, reverse=True)) + r")(?![a-z0-9])", re.I)
URL_RE = re.compile(r"https?://[A-Za-z0-9._~%:\-\[\]]+(?:/[^\s\"'<>]*)?", re.I)
HOST_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
PRIVATE_RE = re.compile(r"(?:[A-Za-z0-9-]+\.)+(?:local|internal|lan|corp|home|test)\b", re.I)
PATH_RE = re.compile(r"/(?:api(?:/v\d+)?|swagger|openapi|api-docs|graphql|graphiql|actuator(?:/[A-Za-z0-9._/-]+)?|debug|metrics|prometheus|admin|internal|mock|sandbox|test|healthz?|readyz?|server-status)(?:[/?#][^\s\"'<>]*)?", re.I)
CONFIG_PATH_RE = re.compile(r"(?:^|/)(?:\.github/workflows/.*\.ya?ml|.*(?:dev|test|stage|staging|uat|preprod).*|\.env(?:\..*)?|docker-compose.*\.ya?ml|compose.*\.ya?ml|application.*\.(?:ya?ml|properties)|bootstrap.*\.ya?ml|config.*\.(?:json|ya?ml|js|ts)|values.*\.ya?ml|Chart\.yaml|vercel\.json|netlify\.toml|firebase\.json|serverless\.ya?ml|.*\.tf|.*\.tfvars)$", re.I)
SECRET_RULES = {
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws-secret-name": re.compile(r"\bAWS_SECRET_ACCESS_KEY\b", re.I),
    "github-token-name": re.compile(r"\b(?:GITHUB_TOKEN|GH_TOKEN)\b", re.I),
    "database-url-name": re.compile(r"\b(?:DATABASE_URL|DB_URL|MONGO(?:DB)?_URI|REDIS_URL)\b", re.I),
    "jwt-secret-name": re.compile(r"\b(?:JWT_SECRET|JWT_KEY|TOKEN_SECRET)\b", re.I),
    "api-key-name": re.compile(r"\b(?:API_KEY|APIKEY|ACCESS_TOKEN|CLIENT_SECRET)\b", re.I),
    "password-name": re.compile(r"\b(?:PASSWORD|PASSWD|DB_PASS|MYSQL_PASSWORD|POSTGRES_PASSWORD)\b", re.I),
    "private-key-marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
COMPONENT_RULES = {
    "argocd": r"\bargo\s?cd\b|argocd", "jenkins": r"\bjenkins\b", "gitlab": r"\bgitlab\b",
    "sonarqube": r"\bsonarqube\b|sonar\.host\.url", "grafana": r"\bgrafana\b",
    "kibana": r"\bkibana\b", "prometheus": r"\bprometheus\b", "jaeger": r"\bjaeger\b",
    "zipkin": r"\bzipkin\b", "minio": r"\bminio\b", "harbor": r"\bharbor\b",
    "portainer": r"\bportainer\b", "phpmyadmin": r"\bphpmyadmin\b", "pgadmin": r"\bpgadmin\b",
    "swagger-ui": r"swagger[- ]ui|swagger-ui", "storybook": r"\bstorybook\b",
    "vite-dev": r"\bvite\b|__vite_ping|/@vite/client", "webpack-dev-server": r"webpack-dev-server|sockjs-node",
    "kubernetes": r"\bkubernetes\b|\bkubectl\b|apiVersion:\s*(?:apps/|v1)", "helm": r"\bhelm\b|Chart\.yaml",
    "terraform": r"\bterraform\b|\.tfstate\b", "vercel": r"\bvercel\b|vercel\.json",
    "netlify": r"\bnetlify\b|netlify\.toml",
}
COMPONENT_RULES = {k: re.compile(v, re.I) for k, v in COMPONENT_RULES.items()}
SECRET_NAME_RE = re.compile(r"(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|database_url|mongo(?:db)?_uri|redis_url)", re.I)


def safe_int(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(1, min(value, maximum))


def read_secret(name: str, file_name: str, default_path: str) -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    path = Path(os.getenv(file_name, default_path))
    return path.read_text(encoding="utf-8", errors="ignore").strip() if path.is_file() else ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def host_of(value: Any) -> str:
    raw = str(value or "").strip().lower().strip(".")
    if "://" in raw:
        try:
            raw = (urlsplit(raw).hostname or "").lower().strip(".")
        except ValueError:
            return ""
    return raw.strip("[]")


def scope(root: Path) -> tuple[list[str], set[str]]:
    domains: set[str] = set()
    ips: set[str] = set()
    for name in ("domains.txt", "domains.all.txt"):
        for value in lines(root / name):
            host = host_of(value.replace("*.", ""))
            if host:
                (ips if is_ip(host) else domains).add(host)
    for value in lines(root / "ips.txt"):
        host = host_of(value)
        if is_ip(host):
            ips.add(host)
    return sorted(domains), ips


def scoped(host: str, domains: list[str], ips: set[str]) -> bool:
    host = host_of(host)
    if not host:
        return False
    return host in ips if is_ip(host) else any(host == root or host.endswith("." + root) for root in domains)


def env_labels(value: str) -> list[str]:
    aliases = {"development": "dev", "testing": "test", "stage": "staging"}
    return sorted({aliases.get(m.group(1).lower(), m.group(1).lower()) for m in ENV_RE.finditer(value or "")})


def component_labels(value: str) -> list[str]:
    return sorted(name for name, pattern in COMPONENT_RULES.items() if pattern.search(value or ""))


def redact(value: str, limit: int = 500) -> str:
    value = value.replace("\x00", "")
    value = re.sub(r"(?i)(https?://[^/\s:@]+:)[^@\s/]+@", r"\1<redacted>@", value)
    value = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "AKIA…REDACTED", value)
    lines_out = []
    for line in value.splitlines():
        if SECRET_NAME_RE.search(line) and re.search(r"[:=]", line):
            line = re.sub(r"([:=]\s*).+$", r"\1<redacted>", line)
        lines_out.append(line)
    return "\n".join(lines_out)[:limit]


def extract(value: str, domains: list[str], ips: set[str]) -> tuple[list[str], list[str], list[str], list[str]]:
    hosts: set[str] = set()
    urls: set[str] = set()
    internal: set[str] = set()
    paths = {m.group(0).rstrip(".,);]")[:400] for m in PATH_RE.finditer(value or "")}
    for m in URL_RE.finditer(value or ""):
        url = normalize_url(m.group(0).rstrip(".,);]"))
        if not url:
            continue
        host = host_of(url)
        if scoped(host, domains, ips):
            hosts.add(host)
            urls.add(url)
        elif PRIVATE_RE.search(host):
            internal.add(host)
    for m in HOST_RE.finditer(value or ""):
        host = host_of(m.group(0))
        if scoped(host, domains, ips):
            hosts.add(host)
    for m in PRIVATE_RE.finditer(value or ""):
        internal.add(host_of(m.group(0)))
    return sorted(hosts), sorted(urls), sorted(internal), sorted(paths)


def request_json(url: str, headers: dict[str, str], timeout: int, max_bytes: int) -> Any:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json", **headers})
    with urlopen(req, timeout=timeout) as response:
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise RuntimeError("response-too-large")
        return json.loads(data.decode("utf-8", errors="replace"))


def github_collect(domains: list[str], token: str, max_queries: int, max_files: int, timeout: int, max_bytes: int) -> tuple[list[dict[str, Any]], list[str]]:
    if not token or not domains:
        return [], ["github-skipped:no-token-or-domain"]
    headers = {"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"}
    queries = []
    for root in domains[:10]:
        queries += [f'"{root}"', f'"{root}" path:.github/workflows', f'"{root}" staging', f'"{root}" dev', f'"{root}" uat', f'"{root}" preprod']
    files: dict[tuple[str, str, str], dict[str, Any]] = {}
    errors: list[str] = []
    for query in list(dict.fromkeys(queries))[:max_queries]:
        if len(files) >= max_files:
            break
        url = "https://api.github.com/search/code?" + urlencode({"q": query, "per_page": min(30, max_files), "page": 1})
        try:
            payload = request_json(url, headers, timeout, max_bytes)
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
                files[key] = {"repository": repo, "path": path, "sha": sha, "api_url": api_url,
                              "html_url": item.get("html_url"), "queries": [query]}
    output = []
    for item in files.values():
        try:
            req = Request(item["api_url"], headers={"User-Agent": USER_AGENT, "Authorization": f"Bearer {token}",
                          "X-GitHub-Api-Version": "2022-11-28", "Accept": "application/vnd.github.raw+json"})
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


def fofa_collect(domains: list[str], email: str, key: str, max_results: int, timeout: int, max_bytes: int) -> tuple[list[dict[str, Any]], list[str]]:
    if not email or not key or not domains:
        return [], ["fofa-skipped:no-credentials-or-domain"]
    fields = "host,ip,port,protocol,domain,title,server,product,product_category,os,country,city,as_number"
    names = fields.split(",")
    output: list[dict[str, Any]] = []
    errors: list[str] = []
    for root in domains[:10]:
        query = f'domain="{root}" || cert="{root}" || host="{root}"'
        params = {"email": email, "key": key, "qbase64": base64.b64encode(query.encode()).decode(),
                  "fields": fields, "size": min(max_results, 10000), "page": 1, "full": "false"}
        try:
            payload = request_json("https://fofa.info/api/v1/search/all?" + urlencode(params), {}, timeout, max_bytes)
        except HTTPError as exc:
            errors.append(f"fofa:{root}:http-{exc.code}")
            continue
        except Exception as exc:
            errors.append(f"fofa:{root}:{type(exc).__name__}")
            continue
        if not isinstance(payload, dict) or payload.get("error"):
            errors.append(f"fofa:{root}:{str((payload or {}).get('errmsg') or 'api-error')[:120]}")
            continue
        for row in payload.get("results", []) if isinstance(payload.get("results"), list) else []:
            if not isinstance(row, list):
                continue
            item = {name: row[i] if i < len(row) else "" for i, name in enumerate(names)}
            item["query_root"] = root
            output.append(item)
            if len(output) >= max_results:
                return output, errors
    return output, errors


def github_analyze(item: dict[str, Any], domains: list[str], ips: set[str]) -> dict[str, Any]:
    content = str(item.get("content") or "")
    path = str(item.get("path") or "")
    combined = path + "\n" + content
    hosts, urls, internal, interfaces = extract(combined, domains, ips)
    secrets = []
    for kind, pattern in SECRET_RULES.items():
        line = next((x for x in content.splitlines() if pattern.search(x)), "")
        if line:
            secrets.append({"type": kind, "evidence": redact(line, 260)})
    workflow: dict[str, Any] = {}
    if path.lower().startswith(".github/workflows/") and yaml is not None:
        try:
            doc = yaml.safe_load(content)
        except Exception:
            doc = None
        if isinstance(doc, dict):
            environments: set[str] = set()
            actions: set[str] = set()
            self_hosted = False
            jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                env = job.get("environment")
                if isinstance(env, str):
                    environments.add(env)
                elif isinstance(env, dict) and env.get("name"):
                    environments.add(str(env["name"]))
                if "self-hosted" in json.dumps(job.get("runs-on")):
                    self_hosted = True
                for step in job.get("steps", []) if isinstance(job.get("steps"), list) else []:
                    use = str(step.get("uses") or "") if isinstance(step, dict) else ""
                    if use and re.search(r"(deploy|vercel|netlify|azure|aws|gcp|kubernetes|helm|docker)", use, re.I):
                        actions.add(use[:300])
            workflow = {"environments": sorted(environments), "self_hosted_runner": self_hosted,
                        "deployment_actions": sorted(actions)}
    environment_source = "\n".join(
        [path, " ".join(hosts), " ".join(urls), " ".join(workflow.get("environments", []))]
    )
    envs = set(env_labels(environment_source))
    return {"source": "github", "repository": item.get("repository"), "path": path, "sha": item.get("sha"),
            "html_url": item.get("html_url"), "queries": item.get("queries") or [],
            "config_like": bool(CONFIG_PATH_RE.search(path)), "environments": sorted(envs),
            "hosts": hosts, "urls": urls, "internal_hosts": internal, "test_interfaces": interfaces,
            "components": component_labels(combined), "secret_indicators": secrets,
            "workflow": workflow, "fetch_error": item.get("fetch_error")}


def fofa_analyze(item: dict[str, Any], domains: list[str], ips: set[str]) -> dict[str, Any]:
    host_url = str(item.get("host") or "")
    domain = host_of(item.get("domain"))
    parsed = host_of(host_url)
    host = domain if scoped(domain, domains, ips) else parsed
    text = " ".join(str(item.get(k) or "") for k in ("host", "domain", "title", "server", "product", "product_category", "os"))
    url = normalize_url(host_url)
    if not (url and scoped(host_of(url), domains, ips)):
        url = ""
    return {"source": "fofa", "query_root": item.get("query_root"), "host": host, "url": url,
            "ip": str(item.get("ip") or ""), "port": item.get("port"), "protocol": item.get("protocol"),
            "domain": domain, "title": redact(str(item.get("title") or ""), 260),
            "server": redact(str(item.get("server") or ""), 180),
            "products": sorted({str(item.get("product") or ""), str(item.get("product_category") or "")} - {""}),
            "os": str(item.get("os") or "")[:160], "environments": env_labels(text),
            "components": component_labels(text), "in_scope_host": bool(host and scoped(host, domains, ips)),
            "associated_ip_only": bool(item.get("ip") and str(item.get("ip")) not in ips)}


def aggregate(github_files: list[dict[str, Any]], fofa_records: list[dict[str, Any]],
              domains: list[str], ips: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Counter]:
    assets: dict[str, dict[str, Any]] = {}
    sensitive: list[dict[str, Any]] = []
    stats: Counter = Counter()

    def get_asset(host: str) -> dict[str, Any] | None:
        host = host_of(host)
        if not host:
            return None
        return assets.setdefault(host, {"host": host, "urls": set(), "ips": set(), "ports": set(),
               "sources": set(), "repositories": set(), "files": set(), "environments": set(),
               "components": set(), "test_interfaces": set(), "internal_hosts": set(), "titles": set(),
               "servers": set(), "products": set(), "evidence": [],
               "scope": "in-scope" if scoped(host, domains, ips) else "associated"})

    for item in github_files:
        stats["github_files"] += 1
        stats["github_config_files"] += int(bool(item.get("config_like")))
        stats["github_workflows"] += int(str(item.get("path") or "").lower().startswith(".github/workflows/"))
        stats["github_fetch_errors"] += int(bool(item.get("fetch_error")))
        for indicator in item.get("secret_indicators") or []:
            sensitive.append({"source": "github", "repository": item.get("repository"), "path": item.get("path"),
                              "type": indicator.get("type"), "evidence": indicator.get("evidence"),
                              "html_url": item.get("html_url")})
        hosts = list(item.get("hosts") or [])
        hosts += [host_of(url) for url in item.get("urls") or [] if host_of(url)]
        for host in dict.fromkeys(hosts):
            asset = get_asset(host)
            if not asset:
                continue
            asset["sources"].add("github")
            asset["repositories"].add(str(item.get("repository") or ""))
            asset["files"].add(str(item.get("path") or ""))
            asset["environments"].update(item.get("environments") or [])
            asset["components"].update(item.get("components") or [])
            asset["test_interfaces"].update(item.get("test_interfaces") or [])
            asset["internal_hosts"].update(item.get("internal_hosts") or [])
            asset["urls"].update(url for url in item.get("urls") or [] if host_of(url) == host)
            if len(asset["evidence"]) < 20:
                asset["evidence"].append({"source": "github", "repository": item.get("repository"),
                                          "path": item.get("path"), "html_url": item.get("html_url")})

    for item in fofa_records:
        stats["fofa_results"] += 1
        asset = get_asset(str(item.get("host") or item.get("domain") or ""))
        if not asset:
            continue
        asset["sources"].add("fofa")
        if item.get("url"):
            asset["urls"].add(str(item["url"]))
        if item.get("ip"):
            asset["ips"].add(str(item["ip"]))
        if item.get("port") not in (None, ""):
            asset["ports"].add(str(item["port"]))
        asset["environments"].update(item.get("environments") or [])
        asset["components"].update(item.get("components") or [])
        if item.get("title"):
            asset["titles"].add(str(item["title"]))
        if item.get("server"):
            asset["servers"].add(str(item["server"]))
        asset["products"].update(item.get("products") or [])
        if len(asset["evidence"]) < 20:
            asset["evidence"].append({"source": "fofa", "query_root": item.get("query_root"),
                                      "ip": item.get("ip"), "port": item.get("port"),
                                      "title": item.get("title")})

    output = []
    for raw in assets.values():
        score = 0
        reasons = []
        if raw["environments"]:
            score += 35 + min(20, len(raw["environments"]) * 5)
            reasons.append("non-production:" + ",".join(sorted(raw["environments"])))
        if raw["components"]:
            score += min(30, len(raw["components"]) * 6)
            reasons.append("dev-components:" + ",".join(sorted(raw["components"])))
        if raw["test_interfaces"]:
            score += min(25, len(raw["test_interfaces"]) * 4)
            reasons.append("test-interfaces:" + str(len(raw["test_interfaces"])))
        if raw["internal_hosts"]:
            score += min(20, len(raw["internal_hosts"]) * 5)
            reasons.append("internal-host-references:" + str(len(raw["internal_hosts"])))
        if "github" in raw["sources"]:
            score += 8
            reasons.append("github-source-evidence")
        if "fofa" in raw["sources"]:
            score += 8
            reasons.append("fofa-exposure-evidence")
        if raw["scope"] == "associated":
            score = max(0, score - 10)
            reasons.append("associated-not-active-scope")
        priority = "P0" if score >= 90 else "P1" if score >= 60 else "P2" if score >= 30 else "P3"
        output.append({"host": raw["host"], "scope": raw["scope"], "priority": priority,
            "risk_score": score, "risk_reasons": reasons, "urls": sorted(raw["urls"]),
            "ips": sorted(raw["ips"]), "ports": sorted(raw["ports"]), "sources": sorted(raw["sources"]),
            "repositories": sorted(x for x in raw["repositories"] if x),
            "files": sorted(x for x in raw["files"] if x)[:100],
            "environments": sorted(raw["environments"]), "components": sorted(raw["components"]),
            "test_interfaces": sorted(raw["test_interfaces"])[:100],
            "internal_hosts": sorted(raw["internal_hosts"])[:100], "titles": sorted(raw["titles"])[:20],
            "servers": sorted(raw["servers"])[:20], "products": sorted(raw["products"])[:20],
            "evidence": raw["evidence"],
            "recommended_validation": [
                "先确认资产归属、DNS/证书和部署时间，避免把历史或第三方托管结果当成当前资产。",
                "对 Dev/Staging/Test 环境优先检查默认凭据、调试接口、测试数据和生产密钥复用。",
                "对 CI/CD 暴露仅核验配置与访问控制，不触发部署、发布或写操作。",
            ]})
    output.sort(key=lambda x: (-x["risk_score"], x["host"]))
    stats["assets"] = len(output)
    stats["non_production_assets"] = sum(bool(x["environments"]) for x in output)
    stats["assets_with_dev_components"] = sum(bool(x["components"]) for x in output)
    stats["assets_with_test_interfaces"] = sum(bool(x["test_interfaces"]) for x in output)
    stats["sensitive_indicators"] = len(sensitive)
    return output, sensitive, stats


def write_outputs(root: Path, assets: list[dict[str, Any]], sensitive: list[dict[str, Any]],
                  github_files: list[dict[str, Any]], fofa_records: list[dict[str, Any]],
                  stats: dict[str, Any], errors: list[str]) -> None:
    dump_jsonl(root / "edge-assets.jsonl", assets)
    dump_jsonl(root / "edge-sensitive-indicators.jsonl", sensitive)
    dump_jsonl(root / "edge-github-files.jsonl", github_files)
    dump_jsonl(root / "edge-fofa-results.jsonl", fofa_records)
    hosts = sorted({x["host"] for x in assets if x.get("scope") == "in-scope"})
    urls = sorted({u for x in assets if x.get("scope") == "in-scope" for u in x.get("urls", [])})
    envs = sorted({f"{env}\t{x['host']}\t{','.join(x.get('sources') or [])}"
                   for x in assets for env in x.get("environments", [])})
    (root / "edge-hosts.txt").write_text("".join(f"{x}\n" for x in hosts), encoding="utf-8")
    (root / "edge-urls.txt").write_text("".join(f"{x}\n" for x in urls), encoding="utf-8")
    (root / "edge-environments.txt").write_text("".join(f"{x}\n" for x in envs), encoding="utf-8")
    summary = dict(stats)
    summary["errors"] = errors[:100]
    (root / "edge-intelligence-stats.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md = [
        "# 被动边缘系统情报", "",
        f"- 关联资产：{summary.get('assets', 0)}",
        f"- 非生产环境：{summary.get('non_production_assets', 0)}",
        f"- GitHub 配置文件：{summary.get('github_config_files', 0)}",
        f"- GitHub Actions：{summary.get('github_workflows', 0)}",
        f"- FOFA 结果：{summary.get('fofa_results', 0)}",
        f"- 敏感配置指示：{summary.get('sensitive_indicators', 0)}（仅保存类型和脱敏证据）", "",
        "> 仅执行被动检索。FOFA 关联 IP 和历史托管结果不会自动扩大主动扫描范围。", "",
        "| 优先级 | 资产 | 环境 | 开发组件 | 测试接口 | 来源 | 关键原因 |",
        "|---|---|---|---|---:|---|---|",
    ]
    for item in [x for x in assets if x["priority"] != "P3"][:250]:
        md.append(
            f"| {item['priority']} | `{item['host']}` | {','.join(item['environments']) or '-'} | "
            f"{','.join(item['components']) or '-'} | {len(item['test_interfaces'])} | "
            f"{','.join(item['sources'])} | {'; '.join(item['risk_reasons'])[:600]} |"
        )
    if errors:
        md += ["", "## 数据源状态", ""]
        md += [f"- `{redact(error, 300)}`" for error in errors[:30]]
    (root / "edge-review.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def load_fixture(path: Path | None) -> list[dict[str, Any]]:
    if not path or not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        values = payload.get("items") or payload.get("results") or []
        return [x for x in values if isinstance(x, dict)] if isinstance(values, list) else []
    return []


def cmd_edge(args: argparse.Namespace) -> int:
    root: Path = args.result_dir
    root.mkdir(parents=True, exist_ok=True)
    domains, ips = scope(root)
    errors: list[str] = []

    if args.github_fixture:
        github_raw = load_fixture(args.github_fixture)
    else:
        token = read_secret("GITHUB_TOKEN", "GITHUB_TOKEN_FILE", "/run/secrets/github_token")
        github_raw, source_errors = github_collect(
            domains, token, args.github_max_queries, args.github_max_files, args.timeout, args.max_bytes
        )
        errors += source_errors

    if args.fofa_fixture:
        fofa_source = load_fixture(args.fofa_fixture)
    else:
        email = read_secret("FOFA_EMAIL", "FOFA_EMAIL_FILE", "/run/secrets/fofa_email")
        key = read_secret("FOFA_KEY", "FOFA_KEY_FILE", "/run/secrets/fofa_key")
        fofa_source, source_errors = fofa_collect(
            domains, email, key, args.fofa_max_results, args.timeout, args.max_bytes
        )
        errors += source_errors

    github_files = [
        x if "secret_indicators" in x and "environments" in x else github_analyze(x, domains, ips)
        for x in github_raw
    ]
    fofa_records = [
        x if "environments" in x and "components" in x else fofa_analyze(x, domains, ips)
        for x in fofa_source
    ]
    assets, sensitive, stats = aggregate(github_files, fofa_records, domains, ips)
    stats.update({
        "scope_domains": len(domains),
        "scope_ips": len(ips),
        "github_enabled": bool(args.github_fixture or read_secret(
            "GITHUB_TOKEN", "GITHUB_TOKEN_FILE", "/run/secrets/github_token")),
        "fofa_enabled": bool(args.fofa_fixture or (
            read_secret("FOFA_EMAIL", "FOFA_EMAIL_FILE", "/run/secrets/fofa_email")
            and read_secret("FOFA_KEY", "FOFA_KEY_FILE", "/run/secrets/fofa_key"))),
    })
    write_outputs(root, assets, sensitive, github_files, fofa_records, stats, errors)
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Passive GitHub/Actions/FOFA edge-system intelligence")
    p.add_argument("result_dir", type=Path)
    p.add_argument("--github-max-queries", type=int, default=safe_int("EDGE_GITHUB_MAX_QUERIES", 36, 100))
    p.add_argument("--github-max-files", type=int, default=safe_int("EDGE_GITHUB_MAX_FILES", 80, 500))
    p.add_argument("--fofa-max-results", type=int, default=safe_int("EDGE_FOFA_MAX_RESULTS", 500, 10000))
    p.add_argument("--timeout", type=int, default=safe_int("EDGE_INTEL_TIMEOUT", 12, 60))
    p.add_argument("--max-bytes", type=int, default=safe_int("EDGE_INTEL_MAX_BYTES", 1048576, 8388608))
    p.add_argument("--github-fixture", type=Path)
    p.add_argument("--fofa-fixture", type=Path)
    p.set_defaults(func=cmd_edge)
    return p


if __name__ == "__main__":
    args = parser().parse_args()
    raise SystemExit(args.func(args))
