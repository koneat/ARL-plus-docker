# -*- coding: utf-8 -*-
"""Automatic Afrog integration for ARL tasks.

Compatible with the Python 3.6 runtime in the ARL worker image. The adapter
records whether Afrog/xray did not run, failed, ran with no findings, or ran
with findings; these states must never be collapsed into a misleading zero.
"""

from __future__ import print_function

import datetime
import json
import os
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse

from app import utils


logger = utils.get_logger()
TRUE_VALUES = set(["1", "true", "yes", "on", "enabled"])


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return bool(default)
    return value.strip().lower() in TRUE_VALUES


def safe_int(name, default, minimum=1, maximum=None):
    try:
        value = int((os.getenv(name) or str(default)).strip())
    except (TypeError, ValueError):
        value = int(default)
    value = max(int(minimum), value)
    if maximum is not None:
        value = min(int(maximum), value)
    return value


def utc_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def normalize_targets(targets, maximum):
    output = []
    seen = set()
    for raw in targets or []:
        target = str(raw or "").strip()
        if not target or target in seen:
            continue
        if not target.startswith(("http://", "https://")):
            continue
        seen.add(target)
        output.append(target)
        if len(output) >= maximum:
            break
    return output


def proxy_endpoint(proxy_url):
    parsed = urlparse(proxy_url or "")
    if not parsed.hostname:
        return None
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    elif parsed.scheme in ("socks5", "socks5h"):
        port = 1080
    else:
        port = 80
    return parsed.hostname, port


def proxy_reachable(proxy_url, timeout=3):
    endpoint = proxy_endpoint(proxy_url)
    if not endpoint:
        return False
    sock = None
    try:
        sock = socket.create_connection(endpoint, timeout=timeout)
        return True
    except Exception as exc:
        logger.warning("xray proxy unavailable {}: {}".format(proxy_url, exc))
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def load_json_results(path):
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return []
    try:
        with open(path, "r") as handle:
            raw = handle.read().strip()
    except Exception as exc:
        logger.warning("read afrog json failed: {}".format(exc))
        return []
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except Exception:
        data = []
        for line in raw.splitlines():
            try:
                item = json.loads(line)
            except Exception:
                continue
            if isinstance(item, dict):
                data.append(item)

    if isinstance(data, dict):
        data = data.get("results") or data.get("data") or data.get("vulnerabilities") or []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def first_value(mapping, *names):
    if not isinstance(mapping, dict):
        return ""
    for name in names:
        value = mapping.get(name)
        if value not in (None, "", [], {}):
            return value
    return ""


def normalize_findings(items):
    """Map official Afrog 3.x JSON and legacy variants to ARL schemas."""
    output = []
    seen = set()
    for item in items:
        pocinfo = item.get("pocinfo") if isinstance(item.get("pocinfo"), dict) else {}
        info = item.get("info") if isinstance(item.get("info"), dict) else {}

        host_target = str(first_value(item, "target", "host") or "")
        vuln_url = str(
            first_value(item, "fulltarget", "full-target", "url", "matched-at")
            or host_target
        )
        poc_id = str(
            first_value(pocinfo, "id")
            or first_value(item, "poc", "poc_name", "poc-name", "id", "template-id")
            or ""
        )
        name = str(
            first_value(pocinfo, "infoname", "name")
            or first_value(info, "name")
            or first_value(item, "vul_name", "vuln_name", "vulnerability", "name")
            or poc_id
            or "Afrog finding"
        )
        severity = str(
            first_value(pocinfo, "infoseg", "severity")
            or first_value(info, "severity")
            or first_value(item, "vuln_severity", "severity", "level")
            or "unknown"
        ).lower()

        key = (poc_id, name, vuln_url)
        if key in seen:
            continue
        seen.add(key)

        summary = {
            "name": name,
            "severity": severity,
            "target": host_target or vuln_url,
            "vuln_url": vuln_url,
            "poc": poc_id,
        }
        output.append(
            {
                # Native generic ARL vuln collection fields.
                "plg_name": "afrog:{}".format(poc_id or "unknown"),
                "plg_type": "poc",
                "vul_name": name,
                "app_name": "Afrog",
                "target": host_target or vuln_url,
                "verify_data": summary,
                # Fields consumed by Nuclei-style result renderers and exports.
                "template_url": "",
                "template_id": poc_id,
                "vuln_name": name,
                "vuln_severity": severity,
                "vuln_url": vuln_url,
                "curl_command": "",
                # Preserve the original Afrog record for evidence/review.
                "scanner": "afrog",
                "verify_obj": item,
            }
        )
    return output


class AfrogTaskScan(object):
    def __init__(self, targets, task_id=None):
        self.task_id = str(task_id or "unknown")
        self.bin_path = os.getenv("ARL_AFROG_BIN", "afrog")
        self.report_root = os.getenv("ARL_REPORT_ROOT", "/var/lib/arl-reports")
        self.max_targets = safe_int("ARL_AFROG_MAX_TARGETS", 3000, 1, 20000)
        self.targets = normalize_targets(targets, self.max_targets)
        self.proxy_url = (os.getenv("ARL_XRAY_PROXY_URL") or "").strip()
        self.require_xray = env_bool("ARL_REQUIRE_XRAY_PROXY", True)
        self.started_at = utc_now()
        self.started_monotonic = time.time()

        stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        safe_task = "".join(
            ch if ch.isalnum() or ch in "-_" else "_" for ch in self.task_id
        )[:80]
        self.base_name = "afrog-{}-{}".format(safe_task or "unknown", stamp)
        self.afrog_dir = os.path.join(self.report_root, "afrog")
        self.json_path = os.path.join(self.afrog_dir, self.base_name + ".json")
        self.html_path = os.path.join(self.afrog_dir, self.base_name + ".html")
        self.status_path = os.path.join(self.afrog_dir, self.base_name + ".status.json")
        self.target_path = None
        self._help_cache = None

    def _status(self, state, **extra):
        elapsed = round(time.time() - self.started_monotonic, 3)
        data = {
            "task_id": self.task_id,
            "engine": "afrog",
            "status": state,
            "started_at": self.started_at,
            "ended_at": utc_now(),
            "elapsed_seconds": elapsed,
            "target_count": len(self.targets),
            "findings_count": int(extra.pop("findings_count", 0) or 0),
            "json_report": self.json_path,
            "html_report": self.html_path,
            "status_report": self.status_path,
            "xray": {
                "proxy_url": self.proxy_url,
                "required": self.require_xray,
                "status": extra.pop("xray_status", "not_executed"),
                "report": os.path.join(self.report_root, "xray", "proxy.html"),
            },
        }
        data.update(extra)
        os.makedirs(self.afrog_dir, exist_ok=True)
        temporary = self.status_path + ".tmp"
        with open(temporary, "w") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, self.status_path)
        try:
            os.chmod(self.status_path, 0o640)
        except Exception:
            pass
        return data

    def _help_text(self):
        if self._help_cache is not None:
            return self._help_cache
        try:
            process = subprocess.run(
                [self.bin_path, "-h"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                close_fds=True,
                timeout=30,
            )
            raw = (process.stdout or b"") + b"\n" + (process.stderr or b"")
            self._help_cache = raw.decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("read afrog help failed: {}".format(exc))
            self._help_cache = ""
        return self._help_cache

    def _supports(self, flag):
        return flag in self._help_text()

    def _write_targets(self):
        handle = tempfile.NamedTemporaryFile(
            mode="w", prefix="arl-afrog-", suffix=".txt", delete=False
        )
        try:
            for target in self.targets:
                handle.write(target + "\n")
        finally:
            handle.close()
        self.target_path = handle.name

    def _cleanup_target(self):
        if not self.target_path:
            return
        try:
            os.unlink(self.target_path)
        except Exception:
            pass
        self.target_path = None

    def _build_command(self):
        command = [
            self.bin_path,
            "-T",
            self.target_path,
            "-j",
            self.json_path,
            "-o",
            self.html_path,
        ]
        optional_values = [
            ("-S", os.getenv("ARL_AFROG_SEVERITY", "info,low,medium,high,critical")),
            ("-rl", str(safe_int("ARL_AFROG_RATE_LIMIT", 100, 1, 1000))),
            ("-c", str(safe_int("ARL_AFROG_CONCURRENCY", 20, 1, 100))),
            ("-timeout", str(safe_int("ARL_AFROG_TIMEOUT", 20, 1, 300))),
        ]
        for flag, value in optional_values:
            if value and self._supports(flag):
                command.extend([flag, value])
        for flag in ("-nc", "-silent"):
            if self._supports(flag):
                command.append(flag)
        if self.proxy_url and self._supports("-proxy"):
            command.extend(["-proxy", self.proxy_url])
        return command

    def _update_indexes(self):
        if os.path.isfile(self.html_path) and os.path.getsize(self.html_path) > 0:
            latest = os.path.join(self.afrog_dir, "latest.html")
            try:
                if os.path.lexists(latest):
                    os.unlink(latest)
                os.symlink(os.path.basename(self.html_path), latest)
            except Exception as exc:
                logger.warning("update afrog latest report failed: {}".format(exc))
        indexer = "/usr/local/bin/arl-report-index"
        if os.path.isfile(indexer) and os.access(indexer, os.X_OK):
            subprocess.run([indexer], check=False, close_fds=True, timeout=60)

    def run(self):
        os.makedirs(self.afrog_dir, exist_ok=True)
        if not self.targets:
            status = self._status(
                "skipped_no_targets", xray_status="not_executed", reason="no HTTP targets"
            )
            return {"findings": [], "status": status}

        if not self._help_text():
            status = self._status(
                "skipped_afrog_unavailable",
                xray_status="not_executed",
                reason="afrog unavailable",
            )
            return {"findings": [], "status": status}

        proxy_ok = bool(self.proxy_url and proxy_reachable(self.proxy_url))
        if self.require_xray and not proxy_ok:
            status = self._status(
                "skipped_xray_unavailable",
                xray_status="unavailable",
                reason="required Chaitin xray proxy is not reachable",
            )
            return {"findings": [], "status": status}

        self._write_targets()
        command = self._build_command()
        if proxy_ok and "-proxy" not in command:
            self._cleanup_target()
            status = self._status(
                "skipped_xray_unsupported",
                xray_status="unsupported",
                reason="installed afrog does not support -proxy",
            )
            return {"findings": [], "status": status}

        logger.info(
            "start afrog_scan targets={} xray_proxy={} command={}".format(
                len(self.targets), bool(proxy_ok), " ".join(command)
            )
        )
        environment = os.environ.copy()
        environment.setdefault("HOME", "/root")
        return_code = None
        error = ""
        try:
            process = subprocess.run(
                command,
                check=False,
                close_fds=True,
                env=environment,
                timeout=safe_int("ARL_AFROG_PROCESS_TIMEOUT", 43200, 60, 86400),
            )
            return_code = process.returncode
        except subprocess.TimeoutExpired:
            return_code = 124
            error = "afrog process timed out"
        except Exception as exc:
            return_code = 127
            error = str(exc)
        finally:
            self._cleanup_target()

        raw_results = load_json_results(self.json_path)
        findings = normalize_findings(raw_results)
        self._update_indexes()
        xray_status = "executed_via_proxy" if proxy_ok else "not_configured_direct_scan"
        if return_code == 0:
            state = "executed_findings" if findings else "executed_zero_findings"
        else:
            state = "failed"
            if proxy_ok:
                xray_status = "attempted_via_proxy_failed"

        status = self._status(
            state,
            findings_count=len(findings),
            xray_status=xray_status,
            return_code=return_code,
            error=error,
        )
        logger.info(
            "end afrog_scan status={} findings={} xray_status={}".format(
                state, len(findings), xray_status
            )
        )
        return {"findings": findings, "status": status}


def afrog_scan(targets, task_id=None):
    return AfrogTaskScan(targets=targets, task_id=task_id).run()
