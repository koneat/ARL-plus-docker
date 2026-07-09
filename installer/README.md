# ARL Full 部署引擎

这里保存可公开审计的部署逻辑。真实 MongoDB URI、ARL/MCP Token、FOFA/Hunter/Quake/ZoomEye/Shodan Key 和 VLESS 节点只保存在服务器本机，不进入 Git 历史。

## 文件职责

- `arl-full-deploy.sh`：入口、参数加载和安全默认值；
- `lib/*.sh`：系统、配置、部署、代理、扫描器和校验模块；
- `arl-full.env.example`：本机配置模板，不含真实密钥；
- `/root/arl-full.env`：生产敏感配置，权限必须为 `600`；
- `/etc/xray-core/vless-nodes.txt`：VLESS 节点，权限必须为 `600`。

部署入口会先把自身和模块复制到临时目录，再更新 Git 仓库，避免运行过程中脚本被 `git pull` 替换。

## 安全默认值

- 本机 MCP：`127.0.0.1:5013`，允许免 Token；
- 外部 MCP：`127.0.0.1:5014`，强制 Token；
- 外部入口不会默认监听 `0.0.0.0`；
- 默认不关闭 UFW；
- 默认 MCP 只读；
- 默认不开启 VLESS、长亭 xray 和完整 Worker 工具扩展；
- 智能泛解析 Worker 默认启用；
- 扫描报告默认不是宿主机全局可读。

生产需要写操作时，在本机配置中显式设置：

```dotenv
MCP_READ_ONLY='false'
```

外部入口确需直接监听公网时才设置：

```dotenv
MCP_EXTERNAL_BIND_IP='0.0.0.0'
```

该入口仍强制 Bearer Token，但更推荐绑定 `127.0.0.1` 后通过 Nginx、Caddy 或 Cloudflare Tunnel 转发。

## 持久化镜像

安装器不再通过 `docker exec pip/yum` 或 `docker cp` 修改运行中的 Worker。

启用：

```dotenv
ENABLE_WORKER_EXTENSIONS='true'
```

会构建持久化增强 Worker，内置：

```text
智能泛解析
Nuclei 结果与 API/文件泄露策略
Afrog
RAD
Chromium
libpcap
PySocks
高价值路径、子域名和口令字典
```

启用 ARL HTTP 代理时，Web 和 Scheduler 也会切换到带持久化 PySocks 的运行时镜像。

成功切换后的镜像选择保存在仓库 `.env`：

```dotenv
ARL_WORKER_IMAGE=...
ARL_WEB_IMAGE=...
ARL_SCHEDULER_IMAGE=...
```

以后普通执行 `docker compose up -d` 不会丢失增强能力。

详细说明见根目录 `ENHANCED_WORKER.md`。

## 静态检查

```bash
cp installer/arl-full.env.example /tmp/arl-full.env
bash installer/arl-full-deploy.sh \
  --env-file /tmp/arl-full.env \
  --check-only
```

`--check-only` 不安装、不联网、不修改系统，用于检查全部模块的 Shell 语法、端口、布尔参数、本机免认证绑定、持久化镜像参数和 VLESS 节点格式。

## 正式执行

```bash
install -m 600 installer/arl-full.env.example /root/arl-full.env
vi /root/arl-full.env
bash installer/arl-full-deploy.sh --env-file /root/arl-full.env
```

部署引擎会按顺序执行：

1. 安装 Docker/Compose 基础依赖；
2. 更新仓库并备份已有配置；
3. 写入 ARL、MongoDB、MCP 双入口配置；
4. 启动并验证 ARL、RabbitMQ、MongoDB、MCP；
5. 检查 VLESS 出口；
6. 构建并安全切换智能或完整增强 Worker；
7. 启用 ARL 代理时构建 Web/Scheduler PySocks 运行时；
8. 可选启动长亭 xray；
9. 自动生成本机 `scanner-secrets/uncover-provider.yaml`；
10. 校验并可选构建独立 Scanner；
11. 输出凭据、日志和扫描命令位置。

## 生产更新保护

部署引擎不会执行 `docker compose down -v`，不会删除 MongoDB 数据卷。

自定义镜像更新脚本都会：

- 备份当前精确镜像；
- 先离线自检；
- 仅重建目标服务并使用 `--no-deps`；
- 检查进程、模块和日志；
- 失败自动回滚；
- 保留 `.env` 中的持久镜像选择。

Worker 更新不会重启 Web、MongoDB、RabbitMQ 或 MCP；Web/Scheduler 代理运行时更新不会重启 Worker、MongoDB、RabbitMQ 或 MCP。
