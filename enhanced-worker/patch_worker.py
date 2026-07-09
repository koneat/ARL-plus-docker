#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply deterministic ARL worker extensions during image build.

The script is intentionally compatible with Python 3.6 from the ARL image.
"""

from __future__ import print_function

import argparse
import io
import os
import sys


FILE_DICT = "/code/app/dicts/file_top_2000.txt"
DOMAIN_DICT = "/code/app/dicts/domain_2w.txt"
INFO_HUNTER = "/code/app/services/infoHunter.py"
NUCLEI_SCAN = "/code/app/services/nuclei_scan.py"
AFROG_SCAN = "/code/app/services/afrog_scan.py"
COMMON_TASK = "/code/app/services/commonTask.py"
PASSWORD_ROOT = "/opt/ARL-NPoC/xing/dicts"


def read_text(path):
    with io.open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def write_text(path, content):
    with io.open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    return read_text(path).splitlines()


def normalize(values):
    output = []
    seen = set()
    for raw in values:
        value = (raw or "").strip()
        if not value or value.startswith("#"):
            continue
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def merge_file(target, additions):
    if not os.path.isfile(target):
        raise RuntimeError("required dictionary missing: {}".format(target))
    merged = normalize(read_lines(target) + list(additions))
    with io.open(target, "w", encoding="utf-8") as handle:
        handle.write("\n".join(merged) + "\n")
    return len(merged)


def patch_info_hunter():
    if not os.path.isfile(INFO_HUNTER):
        print("[WARN] infoHunter.py missing; skip --dc patch")
        return False

    content = read_text(INFO_HUNTER)
    if '"--dc"' in content:
        return False

    needle = '"-J",'
    replacement = '"-J",\n                   "-f",\n                   "--dc",'
    if needle not in content:
        print("[WARN] infoHunter.py does not contain the expected -J option; skip")
        return False

    write_text(INFO_HUNTER, content.replace(needle, replacement, 1))
    return True


def install_python_adapter(source, destination, required_markers):
    if not os.path.isfile(source):
        raise RuntimeError("adapter missing: {}".format(source))
    content = read_text(source)
    for marker in required_markers:
        if marker not in content:
            raise RuntimeError("adapter safety marker missing: {}".format(marker))
    write_text(destination, content)


def install_nuclei_adapter(source):
    install_python_adapter(source, NUCLEI_SCAN, ["ARL_NUCLEI_TAGS", "-jsonl"])


def install_afrog_adapter(source):
    install_python_adapter(
        source,
        AFROG_SCAN,
        ["ARL_XRAY_PROXY_URL", "executed_zero_findings", '"plg_name": "afrog"'],
    )


def indentation(line):
    return len(line) - len(line.lstrip(" \t"))


def find_class_bounds(lines, class_name):
    class_start = None
    prefix = "class {}".format(class_name)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            class_start = index
            break
    if class_start is None:
        raise RuntimeError("class {} not found".format(class_name))

    class_end = len(lines)
    for index in range(class_start + 1, len(lines)):
        line = lines[index]
        if line.strip() and indentation(line) == 0 and not line.lstrip().startswith("#"):
            class_end = index
            break
    return class_start, class_end


def find_method_bounds(lines, class_start, class_end, method_name):
    method_start = None
    prefixes = (
        "    def {}(".format(method_name),
        "    async def {}(".format(method_name),
    )
    for index in range(class_start + 1, class_end):
        if lines[index].startswith(prefixes):
            method_start = index
            break
    if method_start is None:
        raise RuntimeError("WebSiteFetch.{} method not found".format(method_name))

    method_end = class_end
    for index in range(method_start + 1, class_end):
        line = lines[index]
        if line.strip() and indentation(line) <= 4 and not line.lstrip().startswith("#"):
            method_end = index
            break
    return method_start, method_end


def ensure_import(content, import_line):
    if import_line in content:
        return content

    anchors = (
        "from app.services.nuclei_scan import nuclei_scan\n",
        "from app import utils\n",
    )
    for anchor in anchors:
        if anchor in content:
            return content.replace(anchor, anchor + import_line, 1)
    raise RuntimeError("commonTask.py import anchor not found")


def patch_common_task():
    if not os.path.isfile(COMMON_TASK):
        raise RuntimeError("required ARL source missing: {}".format(COMMON_TASK))
    content = read_text(COMMON_TASK)

    if "import os\n" not in content:
        if "import ast\n" in content:
            content = content.replace("import ast\n", "import ast\nimport os\n", 1)
        else:
            content = "import os\n" + content

    import_line = "from app.services.afrog_scan import afrog_scan as run_afrog_scan\n"
    content = ensure_import(content, import_line)

    method_marker = "    def afrog_scan(self):\n"
    if method_marker not in content:
        lines = content.splitlines(True)
        class_start, class_end = find_class_bounds(lines, "WebSiteFetch")
        run_start, _run_end = find_method_bounds(
            lines, class_start, class_end, "run"
        )
        method = '''    def afrog_scan(self):
        logger.info("start afrog_scan, poc_sites:{}".format(len(self.poc_sites)))
        result = run_afrog_scan(list(self.poc_sites), task_id=self.task_id)
        findings = result.get("findings") or []
        status = result.get("status") or {}
        xray_status = (status.get("xray") or {}).get("status", "not_executed")

        if xray_status in ("executed_via_proxy", "attempted_via_proxy_failed"):
            self.base_update_task.update_task_field("status", "xray_scan")
            self.base_update_task.update_services(
                "xray_scan", float(status.get("elapsed_seconds") or 0)
            )
            logger.info(
                "end xray_scan via afrog proxy, status:{} report:{}".format(
                    xray_status, (status.get("xray") or {}).get("report", "")
                )
            )
            self.base_update_task.update_task_field("status", "afrog_scan")

        for item in findings:
            item["task_id"] = self.task_id
            item["save_date"] = utils.curr_date()
            utils.conn_db("vuln").insert_one(item)

        logger.info(
            "end afrog_scan, status:{} result:{} status_report:{}".format(
                status.get("status", "unknown"),
                len(findings),
                status.get("status_report", ""),
            )
        )

'''
        lines.insert(run_start, method)
        content = "".join(lines)

    run_marker = '            self.run_func("afrog_scan", self.afrog_scan)\n'
    if run_marker not in content:
        lines = content.splitlines(True)
        class_start, class_end = find_class_bounds(lines, "WebSiteFetch")
        _run_start, run_end = find_method_bounds(
            lines, class_start, class_end, "run"
        )
        afrog_run_block = '''
        """ *** 自动运行 Afrog，并强制通过长亭 xray Webscan 代理 """
        if os.getenv("ARL_AUTO_AFROG_SCAN", "true").strip().lower() in (
                "1", "true", "yes", "on", "enabled"):
            self.run_func("afrog_scan", self.afrog_scan)
'''
        lines.insert(run_end, afrog_run_block)
        content = "".join(lines)

    required = [
        "run_afrog_scan",
        "class WebSiteFetch",
        "def afrog_scan(self):",
        'self.run_func("afrog_scan", self.afrog_scan)',
        'utils.conn_db("vuln").insert_one(item)',
        'update_services(\n                "xray_scan"',
    ]
    for marker in required:
        if marker not in content:
            raise RuntimeError(
                "commonTask.py Afrog integration marker missing: {}".format(marker)
            )
    write_text(COMMON_TASK, content)


def extend_password_dicts():
    additions = ["%user%@2024", "%user%@2025", "Abc@1234", "000000"]
    changed = 0
    if not os.path.isdir(PASSWORD_ROOT):
        print("[WARN] ARL-NPoC password dictionary directory missing")
        return changed

    for root, _dirs, files in os.walk(PASSWORD_ROOT):
        for name in files:
            if not (name.startswith("password_") and name.endswith(".txt")):
                continue
            path = os.path.join(root, name)
            before = normalize(read_lines(path))
            after = normalize(before + additions)
            if before != after:
                with io.open(path, "w", encoding="utf-8") as handle:
                    handle.write("\n".join(after) + "\n")
                changed += 1
    return changed


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file-dict", required=True)
    parser.add_argument("--domain-dict", required=True)
    parser.add_argument("--nuclei-adapter", required=True)
    parser.add_argument("--afrog-adapter", default="/tmp/afrog_scan.py")
    return parser.parse_args()


def main():
    args = parse_args()
    file_count = merge_file(FILE_DICT, read_lines(args.file_dict))
    domain_count = merge_file(DOMAIN_DICT, read_lines(args.domain_dict))
    info_patched = patch_info_hunter()
    install_nuclei_adapter(args.nuclei_adapter)
    install_afrog_adapter(args.afrog_adapter)
    patch_common_task()
    password_files = extend_password_dicts()

    print("[OK] file dictionary entries: {}".format(file_count))
    print("[OK] domain dictionary entries: {}".format(domain_count))
    print("[OK] infoHunter --dc patched: {}".format(info_patched))
    print("[OK] Afrog/xray task integration: True")
    print("[OK] password dictionaries extended: {}".format(password_files))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("[ERROR] worker extension patch failed: {}".format(exc), file=sys.stderr)
        sys.exit(1)
