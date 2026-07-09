Build through:

```bash
docker compose -f docker-compose.yml -f docker-compose.enhanced-worker.yml build --pull worker
```

The build is validated in `.github/workflows/persistent-runtime-validate.yml`.
