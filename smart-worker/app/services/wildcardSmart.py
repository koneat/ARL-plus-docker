# -*- coding: utf-8 -*-
"""ARL 泛解析域名的二次 HTTP 指纹验证。

兼容 ARL 使用的 Python 3.6。该模块只在候选域名的解析记录命中
随机子域名的泛解析记录时运行，不会改变普通域名的处理流程。
"""

from __future__ import absolute_import

import hashlib
import os
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import urllib3

from app import utils

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = utils.get_logger()


_TRUE_VALUES = set(["1", "true", "yes", "on"])
_PRIORITY_LABELS = set([
    "www", "api", "admin", "app", "dev", "test", "stage", "staging",
    "prod", "portal", "console", "oauth", "sso", "auth", "pay",
    "payment", "static", "upload", "uploads", "docs", "doc", "openapi",
    "swagger", "graphql", "gateway", "manage", "management", "backend",
    "internal", "intranet", "m", "mobile", "h5", "cdn", "assets",
])


def _env_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE_VALUES


def _env_int(name, default, minimum, maximum):
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except Exception:
        logger.warning("invalid %s=%r, use default %s", name, value, default)
        return default
    return max(minimum, min(maximum, parsed))


def _env_float(name, default, minimum, maximum):
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = float(value)
    except Exception:
        logger.warning("invalid %s=%r, use default %s", name, value, default)
        return default
    return max(minimum, min(maximum, parsed))


class WildcardSmartFilter(object):
    """对命中泛解析记录的域名进行 HTTP/HTTPS 差异验证。"""

    def __init__(self, base_domain, wildcard_records=None):
        self.base_domain = (base_domain or "").lower().strip(".")
        self.wildcard_records = set(wildcard_records or [])
        self.enabled = _env_bool("WILDCARD_SMART_FILTER", True)
        self.baseline_samples = _env_int("WILDCARD_BASELINE_SAMPLES", 3, 1, 10)
        self.verify_max = _env_int("WILDCARD_VERIFY_MAX", 500, 1, 5000)
        self.concurrency = _env_int("WILDCARD_HTTP_CONCURRENCY", 20, 1, 100)
        self.timeout = _env_int("WILDCARD_HTTP_TIMEOUT", 6, 2, 30)
        self.body_max = _env_int("WILDCARD_BODY_MAX_BYTES", 262144, 4096, 1048576)
        self.similarity_threshold = _env_float(
            "WILDCARD_SIMILARITY_THRESHOLD", 0.78, 0.50, 1.00
        )
        self.keep_unknown = _env_bool("WILDCARD_KEEP_UNKNOWN_PASSIVE", True)
        self.user_agent = os.getenv(
            "WILDCARD_HTTP_USER_AGENT",
            "Mozilla/5.0 (compatible; ARL-WildcardSmart/1.0)",
        )
        self._baseline_fingerprints = None

    def _is_root_domain(self, domain):
        return (domain or "").lower().strip(".") == self.base_domain

    def _is_candidate(self, info):
        if self._is_root_domain(getattr(info, "domain", "")):
            return False
        for value in list(getattr(info, "ip_list", []) or []):
            if value in self.wildcard_records:
                return True
        for value in list(getattr(info, "record_list", []) or []):
            if value in self.wildcard_records:
                return True
        return False

    def _priority(self, info):
        domain = (getattr(info, "domain", "") or "").lower().strip(".")
        suffix = "." + self.base_domain
        prefix = domain[:-len(suffix)] if domain.endswith(suffix) else domain
        labels = [item for item in prefix.split(".") if item]
        score = 0
        for label in labels:
            if label in _PRIORITY_LABELS:
                score += 100
            if any(token in label for token in _PRIORITY_LABELS):
                score += 20
        score += max(0, 20 - len(labels) * 3)
        score += max(0, 30 - len(prefix))
        return score

    def _random_domain(self):
        token = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(14))
        return "arl-wildcard-{}.{}".format(token, self.base_domain)

    def _normalize_location(self, location):
        if not location:
            return ""
        try:
            parsed = urlparse(location)
            host = (parsed.hostname or "").lower().strip(".")
            if host == self.base_domain or host.endswith("." + self.base_domain):
                host = "<host>"
            port = ":{}".format(parsed.port) if parsed.port else ""
            return "{}://{}{}{}".format(
                (parsed.scheme or "").lower(), host, port, parsed.path or "/"
            )
        except Exception:
            return str(location)[:512].lower()

    def _normalize_body(self, body, domain):
        if body is None:
            body = b""
        if not isinstance(body, bytes):
            body = str(body).encode("utf-8", "ignore")
        body = body[:self.body_max]
        text = body.decode("utf-8", "ignore").lower()
        domain = (domain or "").lower().strip(".")
        if domain:
            text = text.replace(domain, "<host>")
        if self.base_domain:
            pattern = r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.{}".format(
                re.escape(self.base_domain)
            )
            text = re.sub(pattern, "<host>", text, flags=re.I)
        text = re.sub(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            "<uuid>", text, flags=re.I,
        )
        text = re.sub(r"\b[0-9a-f]{24,}\b", "<hex>", text, flags=re.I)
        text = re.sub(r"\b\d{6,}\b", "<number>", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _extract_title(self, text):
        matched = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.I | re.S)
        if not matched:
            return ""
        title = re.sub(r"\s+", " ", matched.group(1)).strip().lower()
        return title[:300]

    def _request_fingerprint(self, scheme, domain):
        url = "{}://{}/".format(scheme, domain)
        try:
            response = requests.get(
                url,
                headers={"User-Agent": self.user_agent, "Accept": "*/*"},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
                stream=True,
            )
            body = response.raw.read(self.body_max, decode_content=True)
            normalized_body = self._normalize_body(body, domain)
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower().strip()
            server = response.headers.get("Server", "").lower().strip()[:200]
            return {
                "scheme": scheme,
                "status": int(response.status_code),
                "title": self._extract_title(normalized_body),
                "server": server,
                "content_type": content_type,
                "location": self._normalize_location(response.headers.get("Location", "")),
                "body_hash": hashlib.sha256(normalized_body.encode("utf-8", "ignore")).hexdigest(),
                "body_length": len(normalized_body),
            }
        except Exception:
            return None

    def _fetch_domain(self, domain):
        output = []
        for scheme in ("https", "http"):
            fingerprint = self._request_fingerprint(scheme, domain)
            if fingerprint:
                output.append(fingerprint)
        return output

    def _build_baselines(self):
        if self._baseline_fingerprints is not None:
            return self._baseline_fingerprints
        domains = [self._random_domain() for _ in range(self.baseline_samples)]
        fingerprints = []
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(domains))) as executor:
            futures = [executor.submit(self._fetch_domain, domain) for domain in domains]
            for future in as_completed(futures):
                try:
                    fingerprints.extend(future.result() or [])
                except Exception as exc:
                    logger.warning("wildcard baseline request failed: %s", exc)
        self._baseline_fingerprints = fingerprints
        logger.info(
            "wildcard smart baseline base=%s samples=%s fingerprints=%s",
            self.base_domain, len(domains), len(fingerprints),
        )
        return fingerprints

    def _similarity(self, left, right):
        score = 0.0
        total = 12.0
        if left.get("status") == right.get("status"):
            score += 2.0
        if left.get("title") == right.get("title"):
            score += 2.0
        if left.get("server") == right.get("server"):
            score += 1.0
        if left.get("content_type") == right.get("content_type"):
            score += 1.0
        if left.get("location") == right.get("location"):
            score += 1.0
        if left.get("body_hash") == right.get("body_hash"):
            score += 4.0
        left_len = int(left.get("body_length") or 0)
        right_len = int(right.get("body_length") or 0)
        maximum = max(left_len, right_len, 1)
        if abs(left_len - right_len) <= 128 or (float(abs(left_len - right_len)) / maximum) <= 0.05:
            score += 1.0
        return score / total

    def _verify_one(self, info, baselines):
        domain = getattr(info, "domain", "")
        fingerprints = self._fetch_domain(domain)
        if not fingerprints:
            return self.keep_unknown, "unknown"
        if not baselines:
            return True, "no-baseline"
        highest = 0.0
        for fingerprint in fingerprints:
            for baseline in baselines:
                highest = max(highest, self._similarity(fingerprint, baseline))
        if highest >= self.similarity_threshold:
            return False, "wildcard-similarity:{:.2f}".format(highest)
        return True, "different:{:.2f}".format(highest)

    def filter_infos(self, domain_info_list):
        if not self.enabled or not self.wildcard_records:
            return list(domain_info_list or [])

        normal = []
        candidates = []
        for info in domain_info_list or []:
            if self._is_root_domain(getattr(info, "domain", "")):
                normal.append(info)
            elif self._is_candidate(info):
                candidates.append(info)
            else:
                normal.append(info)

        if not candidates:
            return normal

        candidates.sort(key=self._priority, reverse=True)
        verify_items = candidates[:self.verify_max]
        overflow = candidates[self.verify_max:]
        baselines = self._build_baselines()
        keep_map = {}
        reason_map = {}

        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(verify_items))) as executor:
            future_map = {
                executor.submit(self._verify_one, info, baselines): info
                for info in verify_items
            }
            for future in as_completed(future_map):
                info = future_map[future]
                domain = getattr(info, "domain", "")
                try:
                    keep, reason = future.result()
                except Exception as exc:
                    keep, reason = self.keep_unknown, "exception:{}".format(exc)
                keep_map[domain] = keep
                reason_map[domain] = reason

        kept = list(normal)
        dropped = len(overflow)
        for info in verify_items:
            domain = getattr(info, "domain", "")
            if keep_map.get(domain, self.keep_unknown):
                kept.append(info)
            else:
                dropped += 1
                logger.debug("wildcard smart drop %s %s", domain, reason_map.get(domain, ""))

        logger.info(
            "wildcard smart filter base=%s input=%s candidates=%s verified=%s "
            "overflow_drop=%s kept=%s dropped=%s",
            self.base_domain,
            len(domain_info_list or []),
            len(candidates),
            len(verify_items),
            len(overflow),
            len(kept),
            dropped,
        )
        return kept
