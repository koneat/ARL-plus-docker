Rollback entry points:

```bash
bash scripts/rollback-enhanced-worker.sh
bash scripts/rollback-proxy-runtime.sh
bash scripts/rollback-smart-wildcard.sh
```

Each script targets only the affected service set and keeps MongoDB volumes untouched.
