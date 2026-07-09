#!/usr/bin/env python3
from pathlib import Path

path = Path('/opt/scanner/run-scan-v2.sh')
text = path.read_text(encoding='utf-8')
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
if old not in text:
    raise SystemExit('run-scan-v2.sh nuclei block not found')
text = text.replace(old, new, 1)
old2 = 'python3 /opt/scanner/render_report.py "$OUT"\n'
new2 = old2 + 'python3 /opt/scanner/finalize_quality.py "$OUT"\n'
if old2 not in text:
    raise SystemExit('render_report invocation not found')
text = text.replace(old2, new2, 1)
path.write_text(text, encoding='utf-8')
