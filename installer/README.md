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
- 默认不启用 VLESS、长亭 xray 和 Worker 运行时扩展；
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

## 静态检查

```bash
cp installer/arl-full.env.example /tmp/arl-full.env
bash installer/arl-full-deploy.sh \
  --env-file /tmp/arl-full.env \
  --check-only
```

`--check-only` 不安装、不联网、不修改系统，用于检查全部模块的 Shell 语法、端口、布尔参数、本机免认证绑定和 VLESS 节点格式。

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
5. 安全切换智能泛解析 Worker，失败自动回滚；
6. 可选安装 VLESS/Xray-core、长亭 xray、Afrog/RAD；
7. 自动生成本机 `scanner-secrets/uncover-provider.yaml`；
8. 校验并可选构建独立 Scanner；
9. 输出凭据、日志和扫描命令位置。

## 生产更新保护

部署引擎不会执行 `docker compose down -v`，不会删除 MongoDB 数据卷。智能泛解析 Worker 使用仓库自带的备份、健康检查和自动回滚脚本，只重建 Worker，不重启 Web、MongoDB、RabbitMQ 或 MCP。

Worker 内通过 `docker cp` 注入的 Afrog/RAD 和字典属于运行时扩展；Worker 被重新创建后需要重新运行部署引擎。独立 Scanner 使用专用镜像，不受这个限制。
