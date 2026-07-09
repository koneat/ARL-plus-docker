prepare_compose_file() {
  local compose_file="${ARL_DIR}/docker-compose.yml"
  [[ -f "$compose_file" ]] || die "仓库缺少 docker-compose.yml"
  backup_file "$compose_file"

  python3 - "$compose_file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

# Compose v2 已忽略 version 字段，删除以避免 obsolete 警告。
lines = text.splitlines(keepends=True)
if lines and lines[0].lstrip().startswith("version:"):
    text = "".join(lines[1:])

old_port = '          - "5003:443"'
new_port = '          - "${ARL_BIND_IP:-0.0.0.0}:${ARL_HTTPS_PORT:-5003}:443"'
if new_port not in text:
    if old_port not in text:
        raise SystemExit("未找到 ARL Web 端口映射，拒绝盲目修改 docker-compose.yml")
    text = text.replace(old_port, new_port, 1)

def section_bounds(source: str, name: str, next_name: str) -> tuple[int, int]:
    start_token = f"    {name}:\n"
    end_token = f"    {next_name}:\n"
    start = source.find(start_token)
    end = source.find(end_token, start + len(start_token))
    if start < 0 or end < 0:
        raise SystemExit(f"未找到 Compose 服务区段：{name}")
    return start, end

report_web = '          - "${ARL_REPORT_ROOT:-/var/lib/arl-reports}:/code/frontend/report:ro"\n'
ws, we = section_bounds(text, "web", "worker")
web_section = text[ws:we]
if report_web.strip() not in web_section:
    anchor = '          - ./poc:/opt/ARL-NPoC/xing/plugins/upload_poc\n'
    if anchor not in web_section:
        raise SystemExit("未找到 web volumes 插入位置")
    web_section = web_section.replace(anchor, anchor + report_web, 1)
    text = text[:ws] + web_section + text[we:]

report_worker = '          - "${ARL_REPORT_ROOT:-/var/lib/arl-reports}:/var/lib/arl-reports"\n'
ws, we = section_bounds(text, "worker", "scheduler")
worker_section = text[ws:we]
if report_worker.strip() not in worker_section:
    anchor = '          - ./poc:/opt/ARL-NPoC/xing/plugins/upload_poc\n'
    if anchor not in worker_section:
        raise SystemExit("未找到 worker volumes 插入位置")
    worker_section = worker_section.replace(anchor, anchor + report_worker, 1)
    text = text[:ws] + worker_section + text[we:]

path.write_text(text, encoding="utf-8")
PY

  ok "ARL Web 端口和扫描报告目录已写入 Compose"
}
