#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p /work/results /root/.config /root/nuclei-templates /opt/pocs/nuclei /opt/pocs/afrog

if [[ "${UPDATE_TEMPLATES:-true}" == "true" ]]; then
  nuclei -ut >/tmp/nuclei-template-update.log 2>&1 || {
    echo '[scanner][WARN] nuclei 模板更新失败，继续使用缓存模板。' >&2
    tail -n 20 /tmp/nuclei-template-update.log >&2 || true
  }
fi

exec "$@"
