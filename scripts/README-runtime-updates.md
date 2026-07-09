# Runtime image update scripts

- `update-smart-wildcard.sh`: smart wildcard Worker with persistent PySocks.
- `rollback-smart-wildcard.sh`: restore the previous Worker.
- `update-enhanced-worker.sh`: full persistent Worker with Nuclei/Afrog/RAD/Chromium/libpcap/dictionaries.
- `rollback-enhanced-worker.sh`: exact enhanced Worker rollback.
- `update-proxy-runtime.sh`: persistent PySocks Web and Scheduler runtime.
- `rollback-proxy-runtime.sh`: exact Web and Scheduler rollback.
- `compose-env.py`: atomic `.env` image selection editor.

All update scripts avoid `docker compose down`, avoid volume deletion and use `--no-deps` for the target services.
