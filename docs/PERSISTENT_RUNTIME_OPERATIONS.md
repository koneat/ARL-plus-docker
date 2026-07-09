Operational checks:

```bash
docker inspect -f '{{.Config.Image}}' arl_worker
docker inspect -f '{{.Config.Image}}' arl_web
docker inspect -f '{{.Config.Image}}' arl_scheduler
docker logs --tail=200 arl_worker
```
