# ARL 智能泛解析过滤

该增强只修改 `arl_worker` 的域名扫描逻辑，不修改 Web、Scheduler、MongoDB、RabbitMQ、MCP、端口和数据卷。

## 解决的问题

ARL 原逻辑会生成一个随机不存在域名，取得其 IP/CNAME 作为泛解析记录。后续只要候选域名命中相同 IP，就立即 `continue` 删除。

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
  -> 生成 3 个随机子域名作为 HTTP/HTTPS 基线
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

参数说明：

- `WILDCARD_BASELINE_SAMPLES`：随机不存在子域名的基线数量；
- `WILDCARD_VERIFY_MAX`：单个任务最多进行 HTTP 指纹验证的泛解析候选数；
- `WILDCARD_HTTP_CONCURRENCY`：并发 HTTP 验证数量；
- `WILDCARD_SIMILARITY_THRESHOLD`：候选与基线达到该相似度时判定为默认泛解析页面；
- `WILDCARD_KEEP_UNKNOWN_PASSIVE`：HTTP/HTTPS 都无法访问时是否保留候选，默认保留以减少漏报。

优先验证包含以下标签的候选：

```text
www api admin app dev test stage staging prod portal console oauth sso auth
pay payment static upload docs openapi swagger graphql gateway manage backend
internal h5 cdn assets
```

超过 `WILDCARD_VERIFY_MAX` 的低优先级候选会被丢弃，避免泛解析任务无限膨胀。

## 生产环境更新

```bash
cd /root/ARL-plus-docker
git fetch origin main
git checkout main
git pull --ff-only origin main
chmod +x scripts/update-smart-wildcard.sh scripts/rollback-smart-wildcard.sh
bash scripts/update-smart-wildcard.sh
```

更新脚本会：

1. 读取现有 `arl_worker` 的精确镜像 ID；
2. 将现有镜像保存为 `arl-worker-backup:<时间戳>`；
3. 构建 `arl-smart-wildcard:v3.0.1`；
4. 在离线容器中检查 Python 3.6 编译和补丁内容；
5. 只重建 `arl_worker`，使用 `--no-deps`；
6. 检查 Celery Worker 进程和模块导入；
7. 发现启动异常时自动恢复原 Worker 镜像。

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

也可以指定历史状态文件：

```bash
bash scripts/rollback-smart-wildcard.sh \
  /root/arl-smart-wildcard-backups/20260708-230000/state.env
```

## 查看运行日志

```bash
docker logs --tail=200 arl_worker
```

智能过滤汇总日志包含：

```text
wildcard smart baseline
wildcard smart filter
```

搜索：

```bash
docker logs arl_worker 2>&1 | grep -E 'wildcard smart (baseline|filter)'
```

## 临时关闭

不需要回滚镜像，可在更新时设置：

```bash
WILDCARD_SMART_FILTER=false bash scripts/update-smart-wildcard.sh
```

此时模块仍存在，但智能 HTTP 过滤不执行。生产环境更建议直接运行回滚脚本恢复原镜像。
