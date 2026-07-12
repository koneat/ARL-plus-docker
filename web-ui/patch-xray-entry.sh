#!/bin/sh
set -eu

INDEX_FILE="${ARL_FRONTEND_INDEX:-/code/frontend/index.html}"
REPORT_WEB_ROOT="${ARL_REPORT_WEB_ROOT:-/code/frontend/report}"
XRAY_WEB_ROOT="${ARL_XRAY_WEB_ROOT:-/code/frontend/xray}"
MARKER='arl-xray-report-entry'

# 不再把宿主机 xray 子目录嵌套挂载到只读 report 挂载点旁边。
# 使用容器内软链接让 /xray/* 与 /report/xray/* 始终读取同一份文件，
# 避免 Docker 嵌套挂载、目录遮蔽和权限状态不一致。
if [ -d "$REPORT_WEB_ROOT/xray" ]; then
  if [ -L "$XRAY_WEB_ROOT" ]; then
    current_target="$(readlink "$XRAY_WEB_ROOT" 2>/dev/null || true)"
    if [ "$current_target" != "$REPORT_WEB_ROOT/xray" ]; then
      rm -f "$XRAY_WEB_ROOT"
    fi
  elif [ -e "$XRAY_WEB_ROOT" ]; then
    if ! rmdir "$XRAY_WEB_ROOT" 2>/dev/null; then
      echo "[WARN] 无法替换非空 Xray Web 目录：$XRAY_WEB_ROOT" >&2
    fi
  fi

  if [ ! -e "$XRAY_WEB_ROOT" ] && [ ! -L "$XRAY_WEB_ROOT" ]; then
    ln -s "$REPORT_WEB_ROOT/xray" "$XRAY_WEB_ROOT"
  fi
fi

if [ ! -f "$INDEX_FILE" ]; then
  echo "[WARN] ARL 前端首页不存在，跳过漏洞报告入口注入：$INDEX_FILE" >&2
  exit 0
fi

if grep -q "$MARKER" "$INDEX_FILE"; then
  echo '[OK] ARL 漏洞报告入口已经存在'
  exit 0
fi

python3 - "$INDEX_FILE" <<'PY'
from __future__ import print_function

import io
import os
import sys

path = sys.argv[1]
marker = "arl-xray-report-entry"

with io.open(path, "r", encoding="utf-8") as handle:
    content = handle.read()

if marker in content:
    raise SystemExit(0)

entry = r'''
<!-- arl-xray-report-entry -->
<a id="arl-xray-report-entry"
   href="/xray/index.html"
   target="_blank"
   rel="noopener noreferrer"
   title="打开 Xray / Afrog 统一漏洞报告"
   style="position:fixed;right:20px;bottom:20px;z-index:2147483647;display:inline-flex;align-items:center;gap:6px;padding:11px 16px;border-radius:999px;background:#0969da;color:#fff;font:600 14px/1.2 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-decoration:none;box-shadow:0 6px 20px rgba(0,0,0,.24);">
  漏洞报告
</a>
'''

if "</body>" in content:
    content = content.replace("</body>", entry + "\n</body>", 1)
else:
    content += entry

temporary = path + ".arl-xray.tmp"
with io.open(temporary, "w", encoding="utf-8") as handle:
    handle.write(content)
os.replace(temporary, path)
PY

echo '[OK] 已在 ARL 5003 页面加入漏洞报告入口：/xray/index.html'
