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
PASSWORD_ROOT = "/opt/ARL-NPoC/xing/dicts"


def read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    with io.open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read().splitlines()


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

    with io.open(INFO_HUNTER, "r", encoding="utf-8") as handle:
        content = handle.read()

    if '"--dc"' in content:
        return False

    needle = '"-J",'
    replacement = '"-J",\n                   "-f",\n                   "--dc",'
    if needle not in content:
        print("[WARN] infoHunter.py does not contain the expected -J option; skip")
        return False

    content = content.replace(needle, replacement, 1)
    with io.open(INFO_HUNTER, "w", encoding="utf-8") as handle:
        handle.write(content)
    return True


def install_nuclei_adapter(source):
    if not os.path.isfile(source):
        raise RuntimeError("nuclei adapter missing: {}".format(source))
    with io.open(source, "r", encoding="utf-8") as handle:
        content = handle.read()
    if "ARL_NUCLEI_TAGS" not in content or "-jsonl" not in content:
        raise RuntimeError("nuclei adapter safety markers missing")
    with io.open(NUCLEI_SCAN, "w", encoding="utf-8") as handle:
        handle.write(content)


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
    return parser.parse_args()


def main():
    args = parse_args()
    file_count = merge_file(FILE_DICT, read_lines(args.file_dict))
    domain_count = merge_file(DOMAIN_DICT, read_lines(args.domain_dict))
    info_patched = patch_info_hunter()
    install_nuclei_adapter(args.nuclei_adapter)
    password_files = extend_password_dicts()

    print("[OK] file dictionary entries: {}".format(file_count))
    print("[OK] domain dictionary entries: {}".format(domain_count))
    print("[OK] infoHunter --dc patched: {}".format(info_patched))
    print("[OK] password dictionaries extended: {}".format(password_files))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("[ERROR] worker extension patch failed: {}".format(exc), file=sys.stderr)
        sys.exit(1)
