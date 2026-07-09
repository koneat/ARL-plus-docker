# shellcheck shell=bash

prepare_reports() {
  install -d -m 0755 "$REPORT_ROOT" "$REPORT_ROOT/xray" "$REPORT_ROOT/afrog"

  if [[ ! -f "$REPORT_ROOT/xray/proxy.html" ]]; then
    cat > "$REPORT_ROOT/xray/proxy.html" <<'HTML'
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>长亭 xray 扫描报告</title></head>
<body><h1>长亭 xray 扫描报告</h1><p>xray Webscan 已启动，发现漏洞后本页面会被报告内容替换。</p></body>
</html>
HTML
  fi

  cat > /usr/local/bin/arl-report-index <<'PY'
#!/usr/bin/env python3
from __future__ import annotations

import html
from pathlib import Path

root = Path(__import__("os").environ.get("ARL_REPORT_ROOT", "/var/lib/arl-reports"))
afrog = root / "afrog"
xray = root / "xray"
root.mkdir(parents=True, exist_ok=True)
afrog.mkdir(parents=True, exist_ok=True)
xray.mkdir(parents=True, exist_ok=True)

reports = sorted(
    (p for p in afrog.glob("*.html") if p.name not in {"index.html", "latest.html"}),
    key=lambda p: p.stat().st_mtime,
    reverse=True,
)

items = []
for p in reports:
    items.append(
        f'<li><a href="{html.escape(p.name)}">{html.escape(p.name)}</a></li>'
    )

afrog_index = f"""<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Afrog 扫描报告</title></head>
<body>
<h1>Afrog 扫描报告</h1>
<ul>
{''.join(items) if items else '<li>目前还没有 Afrog 报告</li>'}
</ul>
<p><a href="../">返回扫描报告首页</a></p>
</body>
</html>
"""
(afrog / "index.html").write_text(afrog_index, encoding="utf-8")

root_index = """<!doctype html>
<html lang="zh-CN">
<head>
<base href="/report/">
<meta charset="utf-8"><title>ARL 扫描报告</title>
</head>
<body>
<h1>ARL 扫描报告</h1>
<p>主入口：<strong>/xray/index.html</strong></p>
<ul>
<li><a href="xray/proxy.html">长亭 xray 实时报告</a></li>
<li><a href="afrog/index.html">Afrog 历史报告</a></li>
</ul>
</body>
</html>
"""
(root / "index.html").write_text(root_index, encoding="utf-8")
(xray / "index.html").write_text(root_index, encoding="utf-8")
PY
  chmod 0755 /usr/local/bin/arl-report-index
  ARL_REPORT_ROOT="$REPORT_ROOT" /usr/local/bin/arl-report-index
  if [[ "$REPORT_WORLD_READABLE" == "true" ]]; then
    chmod -R a+rX "$REPORT_ROOT"
    warn "扫描报告已设为宿主机全局可读；报告可能包含敏感资产信息"
  else
    # 父目录仅允许路径穿越，普通用户无法列目录或读取报告内容。
    # 长亭 xray 的独立服务账户需要穿过 REPORT_ROOT 才能访问自己的 xray 子目录。
    chmod 0711 "$REPORT_ROOT"
    find "$REPORT_ROOT" -mindepth 1 -type d -exec chmod 0750 {} +
    find "$REPORT_ROOT" -type f -exec chmod 0640 {} +
  fi
  ok "报告目录已准备：$REPORT_ROOT；主入口：https://服务器IP:5003/xray/index.html"
}
