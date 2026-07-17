# shellcheck shell=bash

prepare_reports() {
  # Scanner V2 以 root 身份运行，但生产 Compose 会 drop ALL capabilities。
  # 因此不能依赖 CAP_DAC_OVERRIDE：写入目录必须明确归 root 所有。
  install -d -o 0 -g 0 -m 0755 \
    "$REPORT_ROOT" \
    "$REPORT_ROOT/xray" \
    "$REPORT_ROOT/xray/history" \
    "$REPORT_ROOT/afrog" \
    "$REPORT_ROOT/scanner"

  if [[ ! -f "$REPORT_ROOT/xray/proxy.html" ]]; then
    cat > "$REPORT_ROOT/xray/proxy.html" <<'HTML'
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>长亭 xray 扫描报告</title></head>
<body><h1>长亭 xray 扫描报告</h1><p>xray Webscan 已启动，发现漏洞后本页面会被报告内容替换。</p></body>
</html>
HTML
  fi

  if [[ ! -f "$REPORT_ROOT/scanner/index.html" ]]; then
    cat > "$REPORT_ROOT/scanner/index.html" <<'HTML'
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Scanner V2 增强扫描</title></head>
<body><h1>Scanner V2 增强扫描</h1><p>目前还没有 Scanner V2 增强扫描报告。</p></body>
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
<h1>Afrog 扫描任务完整报告</h1>
<p>这里每个文件对应一次 Afrog 扫描任务，不是一个漏洞一个“完整报告”。</p>
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
<li><a href="afrog/index.html">Afrog 扫描任务完整报告</a></li>
<li><a href="scanner/index.html">Scanner V2 增强扫描报告</a></li>
</ul>
</body>
</html>
"""
(root / "index.html").write_text(root_index, encoding="utf-8")
(xray / "index.html").write_text(root_index, encoding="utf-8")
PY
  chmod 0755 /usr/local/bin/arl-report-index
  ARL_REPORT_ROOT="$REPORT_ROOT" /usr/local/bin/arl-report-index

  # 报告已通过 ARL Web 静态目录发布。Web 容器与宿主机 xray 用户通常
  # 不共享 UID/GID，因此 HTML/JSON 必须具备跨容器只读权限，否则会 403。
  find "$REPORT_ROOT" -type d -exec chmod 0755 {} +
  find "$REPORT_ROOT" -type f \( -name '*.html' -o -name '*.json' -o -name '*.txt' -o -name '*.csv' \) -exec chmod 0644 {} +

  # 再次固定 Scanner 顶层目录所有权。现有历史任务子目录不递归改属主，
  # 避免破坏其他服务生成的证据；Scanner 只需拥有顶层目录即可创建新批次。
  chown 0:0 "$REPORT_ROOT/scanner"
  chmod 0755 "$REPORT_ROOT/scanner"

  if [[ "$REPORT_WORLD_READABLE" == "true" ]]; then
    chmod -R a+rX "$REPORT_ROOT"
    warn "扫描报告已设为宿主机全局可读；报告可能包含敏感资产信息"
  else
    # 非静态报告文件仍保持仅属主/属组可读；Web 会读取的报告格式已单独设为 0644。
    find "$REPORT_ROOT" -type f \
      ! -name '*.html' ! -name '*.json' ! -name '*.txt' ! -name '*.csv' \
      -exec chmod 0640 {} +
  fi
  ok "报告目录已准备：$REPORT_ROOT；主入口：https://服务器IP:5003/xray/index.html"
}
