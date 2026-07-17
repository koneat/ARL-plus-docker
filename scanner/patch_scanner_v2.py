#!/usr/bin/env python3
from pathlib import Path

v2_path = Path('/opt/scanner/run-scan-v2.sh')
v2_text = v2_path.read_text(encoding='utf-8')
old = '''if enabled "$NUCLEI_REQUESTED"; then
  log "第三阶段：运行协议分流 Nuclei V2"
  /opt/scanner/run-nuclei-v2.sh "$OUT" "$MODE"
else
  log "Nuclei 已关闭"
fi
'''
new = '''if enabled "$NUCLEI_REQUESTED"; then
  log "第三阶段：运行协议分流 Nuclei V2（失败闭合）"
  set +e
  /opt/scanner/run-nuclei-v2.sh "$OUT" "$MODE"
  NUCLEI_RC=$?
  set -e
  if (( NUCLEI_RC != 0 )); then
    log "WARN: Nuclei V2 未成功完成，rc=${NUCLEI_RC}；状态已写入 nuclei-status.json，继续生成完整报告"
  fi
else
  log "Nuclei 已关闭"
  cat >"$OUT/nuclei-status.json" <<'JSON'
{"engine":"nuclei","status":"disabled","exit_code":0,"findings_count":0,"passes":{}}
JSON
fi
'''
if old not in v2_text:
    raise SystemExit('run-scan-v2.sh nuclei block not found')
v2_text = v2_text.replace(old, new, 1)
old2 = 'python3 /opt/scanner/render_report.py "$OUT"\n'
new2 = old2 + 'python3 /opt/scanner/finalize_quality.py "$OUT"\n'
if old2 not in v2_text:
    raise SystemExit('render_report invocation not found')
v2_text = v2_text.replace(old2, new2, 1)
v2_path.write_text(v2_text, encoding='utf-8')

scan_path = Path('/opt/scanner/run-scan.sh')
scan_text = scan_path.read_text(encoding='utf-8')

old_dnsx = '''dnsx_stage() {
  : >"$OUT/dnsx.jsonl"
  [[ -s "$OUT/domains.all.txt" ]] || return 0
  dnsx -l "$OUT/domains.all.txt" -silent -a -resp -json -o "$OUT/dnsx.jsonl"
}
'''
new_dnsx = '''dnsx_stage() {
  : >"$OUT/dnsx.jsonl"
  : >"$OUT/dnsx.ips.txt"
  [[ -s "$OUT/domains.all.txt" ]] || return 0

  local json_rc=0
  local response_rc=0
  dnsx \\
    -l "$OUT/domains.all.txt" \\
    -silent -a -resp -json -omit-raw -duc \\
    -o "$OUT/dnsx.jsonl" || json_rc=$?

  # 公网域名优先使用 DNSX 官方纯 IP 输出。
  dnsx \\
    -l "$OUT/domains.all.txt" \\
    -silent -a -resp-only -duc \\
    -o "$OUT/dnsx.ips.txt" || response_rc=$?

  # Docker 内部域名、VPN 分流域名和企业私有 DNS 可能只能通过系统解析器
  # 解析。并行调用 getaddrinfo，并从 DNSX JSON 中递归提取所有 IP，最后
  # 统一去重，避免 DNSX 已有结果却被 Naabu 判定为无有效目标。
  python3 - "$OUT/domains.all.txt" "$OUT/dnsx.jsonl" "$OUT/dnsx.ips.txt" <<'PY'
import concurrent.futures
import ipaddress
import json
import socket
import sys
from pathlib import Path

domains_path = Path(sys.argv[1])
json_path = Path(sys.argv[2])
ips_path = Path(sys.argv[3])
values = set()


def add_ip(value):
    if not isinstance(value, str):
        return
    candidate = value.strip().strip('[]')
    try:
        values.add(str(ipaddress.ip_address(candidate)))
    except ValueError:
        pass


def walk(value):
    if isinstance(value, dict):
        for item in value.values():
            walk(item)
    elif isinstance(value, list):
        for item in value:
            walk(item)
    else:
        add_ip(value)

if ips_path.is_file():
    for raw in ips_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        add_ip(raw)

if json_path.is_file():
    for raw in json_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        try:
            walk(json.loads(raw))
        except (TypeError, ValueError):
            continue

hosts = []
if domains_path.is_file():
    hosts = [
        raw.strip().rstrip('.')
        for raw in domains_path.read_text(encoding='utf-8', errors='ignore').splitlines()
        if raw.strip()
    ]


def resolve(host):
    output = set()
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            add = item[4][0]
            try:
                output.add(str(ipaddress.ip_address(add)))
            except ValueError:
                pass
    except OSError:
        pass
    return output

if hosts:
    workers = min(32, max(1, len(hosts)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for resolved in pool.map(resolve, hosts):
            values.update(resolved)

ips_path.write_text(
    ''.join(value + '\\n' for value in sorted(values)),
    encoding='utf-8',
)
PY

  if [[ -s "$OUT/dnsx.jsonl" || -s "$OUT/dnsx.ips.txt" ]]; then
    return 0
  fi
  (( json_rc != 0 )) && return "$json_rc"
  (( response_rc != 0 )) && return "$response_rc"
  return 0
}
'''
if old_dnsx not in scan_text:
    raise SystemExit('run-scan.sh DNSX stage not found')
scan_text = scan_text.replace(old_dnsx, new_dnsx, 1)

old_targets = '''if [[ -s "$OUT/dnsx.jsonl" ]]; then
  jq -r '.host // .input // empty' "$OUT/dnsx.jsonl" | sort -u >"$OUT/dnsx.hosts.txt" || true
else
  : >"$OUT/dnsx.hosts.txt"
fi

cat "$OUT/domains.all.txt" "$OUT/ips.txt" "$OUT/cidrs.txt" 2>/dev/null | \\
  sed '/^[[:space:]]*$/d' | sort -u >"$OUT/portscan.targets.txt"
'''
new_targets = '''if [[ -s "$OUT/dnsx.jsonl" ]]; then
  jq -r '.host // .input // empty' "$OUT/dnsx.jsonl" | sort -u >"$OUT/dnsx.hosts.txt" || true
else
  : >"$OUT/dnsx.hosts.txt"
fi

# 保留原域名，同时复用 DNSX 和系统解析器已经验证的 IP。
cat "$OUT/domains.all.txt" "$OUT/dnsx.ips.txt" "$OUT/ips.txt" "$OUT/cidrs.txt" 2>/dev/null | \\
  sed '/^[[:space:]]*$/d' | sort -u >"$OUT/portscan.targets.txt"
'''
if old_targets not in scan_text:
    raise SystemExit('run-scan.sh DNSX target block not found')
scan_text = scan_text.replace(old_targets, new_targets, 1)

old_naabu = '''naabu_stage() {
  : >"$OUT/naabu.jsonl"
  [[ -s "$OUT/portscan.targets.txt" ]] || return 0
  local args=(
    -list "$OUT/portscan.targets.txt"
    -scan-type c
    -Pn
    -rate "${NAABU_RATE:-500}"
    -retries 1
    -timeout 3000
    -silent
    -json
    -o "$OUT/naabu.jsonl"
  )
  if [[ -n "${CUSTOM_PORTS:-}" ]]; then
    args+=(-p "$CUSTOM_PORTS")
  else
    args+=(-top-ports "$TOP_PORTS")
  fi
  if enabled "$NAABU_SERVICE_VERSION"; then
    args+=(-sV -sV-fast -sV-workers 20)
  fi
  naabu "${args[@]}"
}
'''
new_naabu = '''naabu_stage() {
  : >"$OUT/naabu.jsonl"
  : >"$OUT/naabu.log"
  [[ -s "$OUT/portscan.targets.txt" ]] || return 0
  local args=(
    -list "$OUT/portscan.targets.txt"
    -scan-type c
    -Pn
    -rate "${NAABU_RATE:-500}"
    -retries 1
    -timeout 3000
    -silent
    -json
    -duc
    -no-stdin
    -o "$OUT/naabu.jsonl"
  )
  if [[ -n "${CUSTOM_PORTS:-}" ]]; then
    args+=(-p "$CUSTOM_PORTS")
  else
    args+=(-top-ports "$TOP_PORTS")
  fi
  if enabled "$NAABU_SERVICE_VERSION"; then
    args+=(-sV -sV-fast -sV-workers 20)
  fi
  naabu "${args[@]}" 2> >(tee "$OUT/naabu.log" >&2)
}
'''
if old_naabu not in scan_text:
    raise SystemExit('run-scan.sh Naabu block not found')
scan_text = scan_text.replace(old_naabu, new_naabu, 1)
scan_path.write_text(scan_text, encoding='utf-8')

# Scanner API 的私有状态目录、日志目录和队列事务已经直接维护在源码中。
# 构建阶段只做断言，不再依赖脆弱的字符串替换。
api_path = Path('/opt/scanner/scanner_api.py')
api_text = api_path.read_text(encoding='utf-8')
required = (
    'SCANNER_V2_STATE_ROOT',
    'SCANNER_V2_LOG_ROOT',
    '_submit_lock',
    'def submit_scan(',
    'cleanup_target_file',
)
missing = [item for item in required if item not in api_text]
if missing:
    raise SystemExit('scanner_api.py missing integrated controls: {}'.format(', '.join(missing)))
