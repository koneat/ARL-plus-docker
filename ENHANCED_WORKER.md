# ARL 持久化增强 Worker

本增强把之前通过 `docker exec`、`docker cp` 临时写入 `arl_worker` 的工具和补丁，全部移入可重复构建的自定义镜像。Worker 被重建、服务器重启或再次执行 `docker compose up` 后，增强能力不会消失。

## 镜像内置能力

`arl-enhanced-worker:v3.0.1-2026.07` 基于当前 ARL Worker 镜像构建，包含：

- 智能泛解析候选验证；
- PySocks 持久依赖；
- Chromium；
- libpcap 及兼容软链接；
- Afrog；
- RAD；
- 高价值文件泄露和 API 路径字典；
- 高价值后台、测试环境、支付、钱包、监控和基础设施子域名字典；
- ARL-NPoC 常用口令字典补充；
- `infoHunter.py` 的 `-f --dc` 参数补丁；
- 新版 ARL Nuclei 适配器。

构建过程使用固定版本参数，不再从你的公共仓库下载 Python 文件覆盖运行中容器。

## ARL 内置 Nuclei 修复

旧适配器存在几个问题：

- 只扫描 `cve` 标签，文件泄露、配置泄露和 API 模板不会进入结果；
- JSON 参数检测依赖直接执行不完整命令，不同 Nuclei 版本容易判断失败；
- 结果文件不存在或某行不是合法 JSON 时，整个任务可能报错；
- 命令参数以带空格字符串拼接，兼容性差。

新适配器会从 `nuclei -h` 检测受支持参数，使用参数数组直接执行，并支持：

```dotenv
ARL_NUCLEI_TAGS=cve,exposure,config,files,backup,token,logs,debug,misconfig,api,swagger,openapi,graphql,webhook
ARL_NUCLEI_SEVERITY=info,low,medium,high,critical
ARL_NUCLEI_EXCLUDE_TAGS=dos,fuzz,intrusive,bruteforce
ARL_NUCLEI_RATE_LIMIT=120
```

默认排除 DoS、侵入式、暴力和高噪声 fuzz 模板。

## 安全更新

```bash
cd /root/ARL-plus-docker
git fetch origin main
git checkout main
git pull --ff-only origin main
chmod +x \
  scripts/update-enhanced-worker.sh \
  scripts/rollback-enhanced-worker.sh \
  scripts/compose-env.py
bash scripts/update-enhanced-worker.sh
```

更新脚本会：

1. 记录当前 Worker 的精确镜像 ID；
2. 创建带时间戳的本机备份镜像；
3. 构建增强 Worker；
4. 在离线容器内检查 Python、工具、字典、libpcap 和补丁；
5. 原子写入 `.env` 的 `ARL_WORKER_IMAGE`；
6. 只使用 `--no-deps` 重建 Worker；
7. 检查 Celery、模块导入和启动日志；
8. 失败时自动恢复原 Worker。

不会执行：

```text
docker compose down
docker compose down -v
docker volume rm
MongoDB 迁移
Web、Scheduler、RabbitMQ 或 MCP 重启
```

## 回滚

```bash
cd /root/ARL-plus-docker
bash scripts/rollback-enhanced-worker.sh
```

默认读取：

```text
/root/arl-enhanced-worker-backups/latest.env
```

也可指定历史状态文件：

```bash
bash scripts/rollback-enhanced-worker.sh \
  /root/arl-enhanced-worker-backups/20260709-120000/state.env
```

## Web 与 Scheduler 的 SOCKS 支持

启用 ARL HTTP 代理时，Web 和 Scheduler 使用单独的持久化 PySocks 运行时：

```bash
bash scripts/update-proxy-runtime.sh
```

回滚：

```bash
bash scripts/rollback-proxy-runtime.sh
```

成功切换后，以下镜像选择会保存在仓库 `.env` 中：

```dotenv
ARL_WORKER_IMAGE=arl-enhanced-worker:v3.0.1-2026.07
ARL_WEB_IMAGE=arl-proxy-runtime:v3.0.1-2026.07
ARL_SCHEDULER_IMAGE=arl-proxy-runtime:v3.0.1-2026.07
```

因此普通的 `docker compose up -d` 不会把服务切回基础镜像。

## 查看状态

```bash
docker inspect -f '{{.Config.Image}}' arl_worker
docker exec arl_worker sh -lc 'command -v nuclei afrog rad chromium || true'
docker exec arl_worker python3.6 -c \
  'import socks; from app.services.nuclei_scan import NucleiScan; from app.services.wildcardSmart import WildcardSmartFilter; print("ok")'
docker logs --tail=200 arl_worker
```

Afrog 报告命令：

```bash
docker exec arl_worker afrog-arl -t https://授权目标
```

报告写入：

```text
/var/lib/arl-reports/afrog/
```
