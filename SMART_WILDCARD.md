# ARL 智能泛解析过滤

该增强只修改 `arl_worker` 的域名扫描逻辑，不修改 Web、Scheduler、MongoDB、RabbitMQ、MCP、端口和数据卷。

## 解决的问题

ARL 原逻辑会生成一个随机不存在域名，取得其 IP/CNAME 作为泛解析记录。后续只要候选域名命中相同 IP，就立即删除。

这会误删以下真实资产：

- 与泛解析站点共用 CDN、SLB、反向代理或入口 IP；
- 真实子域名和默认站点解析到同一 IP，但 Host 路由内容不同；
- 根域名自身命中泛解析记录；
- API、后台、测试环境等高价值入口与默认页面共用地址。

## 新处理流程

```text
MassDNS 发现域名
  -> 普通 DNS 记录直接保留
  -> 命中随机域名 IP/CNAME 的记录进入候选队列
  -> 根域名无条件保留
  -> 生成随机子域名作为 HTTP/HTTPS 基线
  -> 比较候选与基线的状态码、标题、Server、Content-Type、Location、正文哈希和正文长度
  -> 与基线高度相似：判定为泛解析默认站点并丢弃
  -> 与基线存在明显差异：作为真实资产保留
  -> 无法完成 HTTP 验证：默认保留，避免漏报
  -> 最后继续执行 ARL 原有的同记录数量限制
```

## 默认参数

```dotenv
WILDCARD_SMART_FILTER=true
WILDCARD_BASELINE_SAMPLES=3
WILDCARD_VERIFY_MAX=500
WILDCARD_HTTP_CONCURRENCY=20
WILDCARD_HTTP_TIMEOUT=6
WILDCARD_BODY_MAX_BYTES=262144
WILDCARD_SIMILARITY_THRESHOLD=0.78
WILDCARD_KEEP_UNKNOWN_PASSIVE=true
```

## 生产环境更新

只启用智能泛解析和持久化 PySocks，不安装 Afrog/RAD/Chromium 等完整扩展：

```bash
cd /root/ARL-plus-docker
git fetch origin main
git checkout main
git pull --ff-only origin main
chmod +x \
  scripts/update-smart-wildcard.sh \
  scripts/rollback-smart-wildcard.sh \
  scripts/compose-env.py
bash scripts/update-smart-wildcard.sh
```

更新脚本会：

1. 读取现有 `arl_worker` 的精确镜像 ID；
2. 保存为带时间戳的备份镜像；
3. 构建智能 Worker；
4. 在离线容器中检查 Python、PySocks 和补丁；
5. 原子写入 `.env` 的 `ARL_WORKER_IMAGE`；
6. 只用 `--no-deps` 重建 Worker；
7. 检查 Celery 和模块导入；
8. 失败时自动恢复原 Worker。

镜像选择写入 `.env` 后，普通 `docker compose up -d` 不会退回基础 Worker。

不会执行：

```text
docker compose down
docker compose down -v
MongoDB 迁移
Web/MCP/Scheduler 重启
密码或 config-docker.yaml 修改
```

## 手工回滚

```bash
cd /root/ARL-plus-docker
bash scripts/rollback-smart-wildcard.sh
```

默认使用：

```text
/root/arl-smart-wildcard-backups/latest.env
```

## 完整增强 Worker

需要同时启用 Nuclei 结果修复、Afrog、RAD、Chromium、libpcap 和高价值字典时，使用：

```bash
bash scripts/update-enhanced-worker.sh
```

详细说明见 `ENHANCED_WORKER.md`。完整增强 Worker 已包含智能泛解析能力，不需要先运行两个更新脚本。
