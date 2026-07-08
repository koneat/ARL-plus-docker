# ARL-Next 安全兼容整合方案

## 目标

在不替换现有 ARL 核心镜像、不修改数据库、不修改密码、不改变现有端口和任务状态机的前提下，逐步吸收 ARL-Next 的工程化长处。

本阶段只新增可选组件。默认部署行为保持不变；只有显式执行 `bash scripts/safe-next-up.sh` 才会启动新增网关。

## 第一阶段已落地

### 1. 可选单入口网关

新增 `docker-compose.next.yml` 和 `next/nginx.conf`：

- 默认监听 `127.0.0.1:5173`；
- 现有 ARL Web `5003` 保留；
- 现有本机 MCP `5013` 保留；
- 现有外部 MCP `5014` 保留；
- `/` 转发到现有 `web` 服务；
- `/mcp` 只转发到强制 Token 的 `mcp` 服务；
- 不转发到免认证的 `mcp-local`；
- 增加基础安全响应头和长连接支持。

### 2. 非破坏启动

`scripts/safe-next-up.sh` 会：

1. 检查 Docker Compose v2；
2. 备份 Compose、配置和 `.env`；
3. 先执行 Compose 渲染校验；
4. 确认现有 `web` 与 `mcp` 已经运行；
5. 使用 `--no-deps` 只启动 `next-gateway`；
6. 健康检查失败时只撤销 `next-gateway`。

脚本不会：

- 执行 `docker compose down`；
- 执行 `down -v`；
- 删除或重建数据卷；
- 自动启动或重建 Web、Worker、Scheduler、MongoDB、RabbitMQ；
- 修改 `config-docker.yaml`；
- 修改管理密码、MongoDB 密码或 RabbitMQ 密码。

### 3. 独立回滚

执行：

```bash
bash scripts/safe-next-rollback.sh
```

只删除新增的 `next-gateway` 容器，不触碰核心服务和数据。

### 4. CI 防回归

GitHub Actions 会校验：

- Shell 脚本语法；
- MCP Python 源码；
- Compose 合并结果；
- Nginx 配置；
- 禁止出现 `down -v`；
- 禁止网关连接免认证 MCP；
- 外部 MCP 仍然强制认证；
- 新网关默认仍然绑定回环地址。

## 使用方法

首次使用：

```bash
cp next/.env.example /tmp/arl-next-env.example
# 将需要的 NEXT_GATEWAY_* 配置写入仓库现有 .env；不需要修改时可直接使用默认值。
bash scripts/safe-next-up.sh
```

验证：

```bash
curl -fsS http://127.0.0.1:5173/healthz
curl -kI http://127.0.0.1:5173/
```

MCP 仍然需要外部入口 Token：

```bash
curl -i http://127.0.0.1:5173/mcp
curl -i -H "Authorization: Bearer $MCP_TOKEN" http://127.0.0.1:5173/mcp
```

## 后续阶段及上线门槛

### 第二阶段：现代扫描 Worker 灰度队列

目标：引入较新的 Chromium、Nuclei、Nmap 和 MassDNS，但不替换现有 Worker。

实施方式：

- 新建独立镜像和独立 Celery 队列，例如 `arltask-next`；
- 默认不接收现有任务；
- 只允许手工选择少量测试任务；
- 新旧 Worker 对同一资产的结果做差异比较；
- 连续通过回归后再逐步增加流量。

上线门槛：

- 旧任务结果数量不下降；
- 截图、域名爆破、端口扫描和 Nuclei 均有可比对结果；
- CPU、内存和任务耗时有基线；
- 随时可把任务路由切回旧队列。

### 第三阶段：企业资产查询侧车

目标：增加 ICP/企业资产查询能力，但不修改 ARL 核心数据库结构。

实施方式：

- 独立 Sidecar API；
- 查询结果先写独立集合或导出文件；
- 人工确认后才导入 ARL 任务；
- API Key 只从私密环境变量读取。

### 第四阶段：新前端并行运行

目标：增加现代化 Vue/Vite 界面，但旧前端继续保留。

实施方式：

- 新前端使用独立端口；
- 只调用现有公开 REST API；
- 不直接连接 MongoDB；
- 登录、任务创建、结果查询全部做端到端回归；
- 验证完成前不替换现有 Web。

### 第五阶段：核心源码可重建

目标：逐步消除对单一预构建核心镜像的依赖。

实施方式：

- 新镜像使用新标签，不覆盖 `ki9mu/arl-ki9mu:v3.0.1`；
- 先构建、扫描和测试，再通过 Compose 环境变量选择镜像；
- 数据库迁移必须单独备份并提供向下回滚；
- 未完成数据兼容验证前禁止切换生产环境。

## 代码来源与许可边界

ARL-Next 当前仓库未发现明确的根目录开源许可证文件。因此，本整合方案只借鉴架构思想并独立实现兼容组件，不直接复制其受版权保护的源代码。后续若需要移植具体实现，应先取得明确许可证或作者授权，并保留原作者声明。
