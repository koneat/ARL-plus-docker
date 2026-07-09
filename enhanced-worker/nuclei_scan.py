# -*- coding: utf-8 -*-
"""ARL Nuclei adapter with robust flag detection and exposure/API policies.

Compatible with the Python 3.6 runtime used by the ARL v3.0.1 image.
"""

import json
import os
import subprocess

from app.config import Config
from app import utils


logger = utils.get_logger()


class NucleiScan(object):
    def __init__(self, targets):
        self.targets = targets
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.nuclei_target_path = os.path.join(
            tmp_path, "nuclei_target_{}.txt".format(rand_str)
        )
        self.nuclei_result_path = os.path.join(
            tmp_path, "nuclei_result_{}.jsonl".format(rand_str)
        )
        self.nuclei_bin_path = os.getenv("ARL_NUCLEI_BIN", "nuclei")
        self.nuclei_json_flag = None
        self._help_cache = None

    @staticmethod
    def _env(name, default):
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip()

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
            logger.warning("nuclei does not expose -jsonl or -json in help output")
        return self.nuclei_json_flag

    def _delete_file(self):
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

    def _gen_target_file(self):
        seen = set()
        with open(self.nuclei_target_path, "w") as handle:
            for target in self.targets:
                target = (target or "").strip()
                if not target or target in seen:
                    continue
                seen.add(target)
                handle.write(target + "\n")
        return len(seen)

    def dump_result(self):
        results = []
        if not os.path.isfile(self.nuclei_result_path):
            return results

        with open(self.nuclei_result_path, "r") as handle:
            for line_number, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception as exc:
                    logger.warning(
                        "skip invalid nuclei JSON line {}: {}".format(line_number, exc)
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
        if self._supports("-stats-interval"):
            command.extend(["-stats-interval", "60"])
        command.extend(["-o", self.nuclei_result_path])
        return command

    def exec_nuclei(self):
        count = self._gen_target_file()
        if count == 0:
            return 0

        command = self._build_command()
        logger.info("exec nuclei targets={} command={}".format(count, " ".join(command)))
        process = subprocess.run(
            command,
            timeout=12 * 60 * 60,
            check=False,
            close_fds=True,
        )
        if process.returncode != 0:
            logger.warning("nuclei exited with code {}".format(process.returncode))
        return process.returncode

    def run(self):
        if not self.check_have_nuclei():
            logger.warning("not found nuclei")
            return []

        if not self._check_json_flag():
            return []

        try:
            self.exec_nuclei()
            results = self.dump_result()
            logger.info("nuclei findings {}".format(len(results)))
            return results
        finally:
            self._delete_file()


def nuclei_scan(targets):
    if not targets:
        return []
    return NucleiScan(targets=targets).run()
