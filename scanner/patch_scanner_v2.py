#!/usr/bin/env python3
from pathlib import Path

runner_path = Path('/opt/scanner/run-scan-v2.sh')
runner_text = runner_path.read_text(encoding='utf-8')
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
if old not in runner_text:
    raise SystemExit('run-scan-v2.sh nuclei block not found')
runner_text = runner_text.replace(old, new, 1)
old2 = 'python3 /opt/scanner/render_report.py "$OUT"\n'
new2 = old2 + 'python3 /opt/scanner/finalize_quality.py "$OUT"\n'
if old2 not in runner_text:
    raise SystemExit('render_report invocation not found')
runner_text = runner_text.replace(old2, new2, 1)
runner_path.write_text(runner_text, encoding='utf-8')

api_path = Path('/opt/scanner/scanner_api.py')
api_text = api_path.read_text(encoding='utf-8')
api_text = api_text.replace(
    'STATE_ROOT = RESULT_ROOT / ".scanner-api"\n',
    'STATE_ROOT = Path(os.getenv("SCANNER_V2_STATE_ROOT", "/root/.config/scanner-api"))\n'
    'LOG_ROOT = Path(os.getenv("SCANNER_V2_LOG_ROOT", str(STATE_ROOT / "logs")))\n',
    1,
)
api_text = api_text.replace(
    '        "log": f"{base}/scanner-api.log",\n',
    '',
    1,
)
api_text = api_text.replace(
    '    log_path = out / "scanner-api.log"\n',
    '    LOG_ROOT.mkdir(parents=True, exist_ok=True)\n'
    '    log_path = LOG_ROOT / f"{scan_id}.log"\n',
    1,
)
api_text = api_text.replace(
    '    STATE_ROOT.mkdir(parents=True, exist_ok=True)\n    INPUT_ROOT.mkdir(parents=True, exist_ok=True)\n',
    '    STATE_ROOT.mkdir(parents=True, exist_ok=True)\n'
    '    LOG_ROOT.mkdir(parents=True, exist_ok=True)\n'
    '    INPUT_ROOT.mkdir(parents=True, exist_ok=True)\n',
    1,
)
if 'SCANNER_V2_STATE_ROOT' not in api_text or 'LOG_ROOT / f"{scan_id}.log"' not in api_text:
    raise SystemExit('scanner_api.py private state patch failed')
api_path.write_text(api_text, encoding='utf-8')
