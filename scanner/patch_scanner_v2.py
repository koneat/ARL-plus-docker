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
