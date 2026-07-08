#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Patch the ARL 2.6.2/v3.0.1 worker source during Docker build.

The patch is deliberately strict: if the expected upstream code is not found,
the image build fails rather than producing a partially modified worker.
"""

from __future__ import print_function

import io
import os
import re
import sys


MASSDNS_PATH = "/code/app/services/massdns.py"
DOMAIN_PATH = "/code/app/tasks/domain.py"


def read_text(path):
    with io.open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def write_text(path, content):
    with io.open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def patch_massdns(content):
    old = '''                # 泛解析域名IP  直接过滤掉
                if record in self.wildcard_domain_ip:
                    continue
'''
    new = '''                # 智能泛解析模式：DNS 命中只标记为候选，不在此处直接删除。
                # HTTP/HTTPS 指纹差异验证由 DomainTask.clear_domain_info_by_record 完成。
'''
    if old not in content:
        raise RuntimeError("massdns.py expected wildcard-drop block not found")
    content = content.replace(old, new, 1)
    if "if record in self.wildcard_domain_ip:\n                    continue" in content:
        raise RuntimeError("massdns.py still contains direct wildcard drop")
    return content


def patch_domain(content):
    import_line = "from app.services.wildcardSmart import WildcardSmartFilter\n"
    anchor = "from app.services.commonTask import CommonTask, WebSiteFetch, build_url_item\n"
    if import_line not in content:
        if anchor not in content:
            raise RuntimeError("domain.py import anchor not found")
        content = content.replace(anchor, anchor + import_line, 1)

    pattern = re.compile(
        r"    def clear_domain_info_by_record\(self, domain_info_list\):\n"
        r".*?"
        r"\n    def arl_search\(self\):\n",
        flags=re.S,
    )
    replacement = '''    def clear_domain_info_by_record(self, domain_info_list):
        # 第一层：普通记录直接保留；命中泛解析记录的候选进入 HTTP 指纹差异验证。
        smart_filter = WildcardSmartFilter(
            self.base_domain,
            wildcard_records=self.not_found_domain_ips,
        )
        filtered_list = smart_filter.filter_infos(domain_info_list)

        # 第二层：保留 ARL 原有的同记录数量限制，防止单一记录造成结果爆炸。
        # 根域名始终保留，不受泛解析和 MAX_MAP_COUNT 限制。
        new_list = []
        for info in filtered_list:
            current_domain = (getattr(info, "domain", "") or "").lower().strip(".")
            if current_domain == self.base_domain.lower().strip("."):
                new_list.append(info)
                continue

            if not info.record_list or not info.ip_list:
                continue

            record = info.record_list[0]
            cnt = self.record_map.get(record, 0)
            cnt += 1
            self.record_map[record] = cnt
            if cnt > MAX_MAP_COUNT:
                continue

            new_list.append(info)

        return new_list

    def arl_search(self):
'''
    patched, count = pattern.subn(replacement, content, count=1)
    if count != 1:
        raise RuntimeError("domain.py clear_domain_info_by_record block not found or ambiguous")
    if "if ip in self.not_found_domain_ips" in patched:
        raise RuntimeError("domain.py still contains direct wildcard-IP drop")
    if "WildcardSmartFilter(" not in patched:
        raise RuntimeError("domain.py smart filter call missing")
    return patched


def main():
    for path in (MASSDNS_PATH, DOMAIN_PATH):
        if not os.path.isfile(path):
            raise RuntimeError("required ARL source file missing: {}".format(path))

    massdns = patch_massdns(read_text(MASSDNS_PATH))
    domain = patch_domain(read_text(DOMAIN_PATH))

    write_text(MASSDNS_PATH, massdns)
    write_text(DOMAIN_PATH, domain)

    print("[OK] patched {}".format(MASSDNS_PATH))
    print("[OK] patched {}".format(DOMAIN_PATH))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("[ERROR] ARL wildcard patch failed: {}".format(exc), file=sys.stderr)
        sys.exit(1)
