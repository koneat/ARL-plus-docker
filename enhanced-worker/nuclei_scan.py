# -*- coding: utf-8 -*-
"""ARL Nuclei adapter with fail-visible runtime status.

Compatible with Python 3.6 used by the ARL v3.0.1 image.
"""

from __future__ import print_function

import io
import json
import os
import subprocess
import time

from app.config import Config
from app import utils


logger = utils.get_logger()


class NucleiScan(object):
    def __init__(self, targets):
        self.targets = targets
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.run_id = "{}-{}".format(int(time.time()), rand_str)
        self.nuclei_target_path = os.path.join(
            tmp_path, "nuclei_target_{}.txt".format(rand_str)
        )
        self.nuclei_result_path = os.path.join(
            tmp_path, "nuclei_result_{}.jsonl".format(rand_str)
        )
        self.nuclei_bin_path = os.getenv("ARL_NUCLEI_BIN", "nuclei")
        self.template_dir = os.getenv(
            "ARL_NUCLEI_TEMPLATE_DIR", "/root/nuclei-templates"
        ).strip()
        self.template_minimum = self._positive_int(
            "ARL_NUCLEI_TEMPLATE_MIN_COUNT", 50
        )
        self.status_dir = os.getenv(
            "ARL_NUCLEI_STATUS_DIR", "/var/lib/arl-reports/nuclei"
        ).strip()
        self.log_path = os.path.join(
            self.status_dir, "{}.log".format(self.run_id)
        )
        self.status_path = os.path.join(
            self.status_dir, "{}.status.json".format(self.run_id)
        )
        self.nuclei_json_flag = None
        self._help_cache = None

    @staticmethod
    def _env(name, default):
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip()

    @staticmethod
    def _positive_int(name, default):
        try:
            value = int(os.getenv(name, str(default)).strip())
        except (TypeError, ValueError):
            return default
        return value if value > 0 else default

    def _ensure_status_dir(self):
        if not self.status_dir:
            return False
        try:
            if not os.path.isdir(self.status_dir):
                os.makedirs(self.status_dir)
            return True
        except OSError as exc:
            logger.error("create nuclei status directory failed: {}".format(exc))
            return False

    def _write_status(
        self,
        status,
        exit_code=0,
        target_count=0,
        findings_count=0,
        template_count=0,
        command=None,
        error="",
    ):
        payload = {
            "engine": "nuclei",
            "run_id": self.run_id,
            "status": status,
            "exit_code": int(exit_code),
            "target_count": int(target_count),
            "findings_count": int(findings_count),
            "template_dir": self.template_dir,
            "template_count": int(template_count),
            "minimum_expected": int(self.template_minimum),
            "command": command or [],
            "log": self.log_path,
            "error": error,
            "created_at": utils.curr_date(),
        }
        if not self._ensure_status_dir():
            return payload
        temporary = self.status_path + ".tmp"
        try:
            with io.open(temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write(u"\n")
            os.rename(temporary, self.status_path)

            latest_path = os.path.join(self.status_dir, "latest.status.json")
            latest_temporary = latest_path + ".tmp"
            with io.open(latest_temporary, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write(u"\n")
            os.rename(latest_temporary, latest_path)
        except Exception as exc:
            logger.error("write nuclei status failed: {}".format(exc))
            try:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            except OSError:
                pass
        return payload

    def _help_text(self):
        if self._help_cache is not None:
            return self._help_cache
        try:
            process = subprocess.run(
                [self.nuclei_bin_path, "-h"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                close_fds=True,
                timeout=30,
            )
            raw = (process.stdout or b"") + b"\n" + (process.stderr or b"")
            self._help_cache = raw.decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("read nuclei help failed: {}".format(exc))
            self._help_cache = ""
        return self._help_cache

    def _supports(self, flag):
        return flag in self._help_text()

    def _check_json_flag(self):
        help_text = self._help_text()
        if "-jsonl" in help_text:
            self.nuclei_json_flag = "-jsonl"
        elif "-json" in help_text:
            self.nuclei_json_flag = "-json"
        else:
            logger.error("nuclei does not expose -jsonl or -json")
        return self.nuclei_json_flag

    def _delete_temporary_files(self):
        for path in (self.nuclei_target_path, self.nuclei_result_path):
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except Exception as exc:
                logger.warning("delete nuclei temporary file failed: {}".format(exc))

    def check_have_nuclei(self):
        try:
            process = subprocess.run(
                [self.nuclei_bin_path, "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                close_fds=True,
                timeout=30,
            )
            return process.returncode == 0
        except Exception as exc:
            logger.debug(str(exc))
            return False

    def _count_templates(self):
        count = 0
        if not self.template_dir or not os.path.isdir(self.template_dir):
            return count
        for root, _dirs, files in os.walk(self.template_dir):
            for name in files:
                if name.endswith((".yaml", ".yml")):
                    count += 1
        return count

    def _gen_target_file(self):
        seen = set()
        with io.open(self.nuclei_target_path, "w", encoding="utf-8") as handle:
            for target in self.targets:
                target = (target or "").strip()
                if not target or target in seen:
                    continue
                seen.add(target)
                handle.write(target + u"\n")
        return len(seen)

    def dump_result(self):
        results = []
        if not os.path.isfile(self.nuclei_result_path):
            return results

        with io.open(self.nuclei_result_path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception as exc:
                    logger.warning(
                        "skip invalid nuclei JSON line {}: {}".format(
                            line_number, exc
                        )
                    )
                    continue

                info = data.get("info") or {}
                item = {
                    "template_url": data.get("template-url", ""),
                    "template_id": data.get("template-id", ""),
                    "vuln_name": info.get("name", ""),
                    "vuln_severity": info.get("severity", ""),
                    "vuln_url": data.get("matched-at", ""),
                    "curl_command": data.get("curl-command", ""),
                    "target": data.get("host", ""),
                }
                results.append(item)
        return results

    def _append_flag_value(self, command, flag, value):
        value = (value or "").strip()
        if value and self._supports(flag):
            command.extend([flag, value])

    def _build_command(self):
        command = [self.nuclei_bin_path]

        for flag in ("-duc", "-no-color"):
            if self._supports(flag):
                command.append(flag)

        tags = self._env(
            "ARL_NUCLEI_TAGS",
            "cve,exposure,config,files,backup,token,logs,debug,misconfig,"
            "api,swagger,openapi,graphql,webhook",
        )
        severity = self._env(
            "ARL_NUCLEI_SEVERITY", "info,low,medium,high,critical"
        )
        exclude_tags = self._env(
            "ARL_NUCLEI_EXCLUDE_TAGS", "dos,fuzz,intrusive,bruteforce"
        )

        self._append_flag_value(command, "-t", self.template_dir)
        self._append_flag_value(command, "-tags", tags)
        self._append_flag_value(command, "-exclude-tags", exclude_tags)
        self._append_flag_value(command, "-severity", severity)
        self._append_flag_value(command, "-type", "http")
        self._append_flag_value(
            command, "-rate-limit", self._env("ARL_NUCLEI_RATE_LIMIT", "120")
        )
        self._append_flag_value(
            command, "-bulk-size", self._env("ARL_NUCLEI_BULK_SIZE", "20")
        )
        self._append_flag_value(
            command, "-timeout", self._env("ARL_NUCLEI_TIMEOUT", "10")
        )
        self._append_flag_value(
            command, "-retries", self._env("ARL_NUCLEI_RETRIES", "1")
        )

        command.extend(["-l", self.nuclei_target_path])
        command.append(self.nuclei_json_flag)

        if self._supports("-stats"):
            command.append("-stats")
        if self._supports("-stats-json"):
            command.append("-stats-json")
        if self._supports("-stats-interval"):
            command.extend(["-stats-interval", "60"])
        command.extend(["-o", self.nuclei_result_path])
        return command

    def _execute(self, command):
        self._ensure_status_dir()
        with io.open(self.log_path, "wb") as handle:
            process = subprocess.run(
                command,
                stdout=handle,
                stderr=subprocess.STDOUT,
                timeout=12 * 60 * 60,
                check=False,
                close_fds=True,
            )
        return process.returncode

    def run(self):
        template_count = self._count_templates()
        target_count = 0
        command = []
        try:
            if not self.check_have_nuclei():
                self._write_status(
                    "failed_binary_missing",
                    exit_code=127,
                    template_count=template_count,
                    error="nuclei binary unavailable",
                )
                logger.error("not found nuclei; status={}".format(self.status_path))
                return []

            if template_count < self.template_minimum:
                self._write_status(
                    "failed_templates_missing",
                    exit_code=20,
                    template_count=template_count,
                    error="template count {} < {}".format(
                        template_count, self.template_minimum
                    ),
                )
                logger.error(
                    "nuclei templates missing count={} minimum={} status={}".format(
                        template_count, self.template_minimum, self.status_path
                    )
                )
                return []

            if not self._check_json_flag():
                self._write_status(
                    "failed_incompatible_binary",
                    exit_code=21,
                    template_count=template_count,
                    error="missing JSON output flag",
                )
                return []

            if not self._supports("-t"):
                self._write_status(
                    "failed_incompatible_binary",
                    exit_code=22,
                    template_count=template_count,
                    error="missing -t template selector",
                )
                return []

            target_count = self._gen_target_file()
            if target_count == 0:
                self._write_status(
                    "skipped_no_targets",
                    target_count=0,
                    template_count=template_count,
                )
                return []

            command = self._build_command()
            logger.info(
                "exec nuclei targets={} templates={} status={} command={}".format(
                    target_count,
                    template_count,
                    self.status_path,
                    " ".join(command),
                )
            )
            return_code = self._execute(command)
            if return_code != 0:
                self._write_status(
                    "failed_command",
                    exit_code=return_code,
                    target_count=target_count,
                    template_count=template_count,
                    command=command,
                    error="nuclei exited with code {}".format(return_code),
                )
                logger.error(
                    "nuclei failed rc={} log={} status={}".format(
                        return_code, self.log_path, self.status_path
                    )
                )
                return []

            results = self.dump_result()
            status = "completed_findings" if results else "executed_zero_findings"
            self._write_status(
                status,
                exit_code=0,
                target_count=target_count,
                findings_count=len(results),
                template_count=template_count,
                command=command,
            )
            logger.info(
                "nuclei status={} findings={} report={}".format(
                    status, len(results), self.status_path
                )
            )
            return results
        except subprocess.TimeoutExpired as exc:
            self._write_status(
                "failed_timeout",
                exit_code=124,
                target_count=target_count,
                template_count=template_count,
                command=command,
                error=str(exc),
            )
            logger.error("nuclei timeout status={}".format(self.status_path))
            return []
        except Exception as exc:
            self._write_status(
                "failed_exception",
                exit_code=-1,
                target_count=target_count,
                template_count=template_count,
                command=command,
                error=str(exc),
            )
            logger.exception("nuclei adapter exception")
            return []
        finally:
            self._delete_temporary_files()


def nuclei_scan(targets):
    if not targets:
        return []
    return NucleiScan(targets=targets).run()
