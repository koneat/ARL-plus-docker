# GitHub / Actions / FOFA 被动边缘系统情报

该模块用于在授权范围内补充 Scanner V2 的边缘资产信息，重点识别：

- `dev`、`test`、`qa`、`uat`、`staging`、`preprod`、`preview`、`sandbox`、`demo` 等非生产环境。
- GitHub 源码、配置文件和 `.github/workflows/*.yml` 中出现的部署 URL、环境名称、自托管 Runner 与部署组件。
- 内部域名引用、测试接口、Swagger/OpenAPI、Actuator、GraphQL、Debug、Metrics 和管理接口。
- Jenkins、Argo CD、SonarQube、Grafana、Kibana、Prometheus、MinIO、Harbor、Portainer、Storybook、Vite、Webpack Dev Server 等开发或运维组件。
- FOFA 返回的域名、端口、产品、标题、服务端信息和关联 IP。

## 安全边界

- 该模块只执行 GitHub 与 FOFA 被动检索，不进行登录、口令尝试或接口写操作。
- GitHub 中识别到的密码、Token、数据库连接串和私钥只保存“类型 + 脱敏证据”，不保存明文值。
- FOFA 返回的关联 IP、历史地址或第三方托管结果不会自动扩大主动扫描范围。
- `EDGE_INTEL_FEED_SCAN` 默认是 `false`。只有显式设置为 `true` 时，范围内的 HTTP URL 才会加入当前扫描 URL 列表。
- 外部域名不会写入 `edge-hosts.txt` 或 `edge-urls.txt`。
- 优先使用任务原始根域 `domains.txt`；只有该文件为空时才回退到 `domains.all.txt`，避免把已发现子域误当成独立检索根域。

## 凭据配置

推荐通过 `scanner-secrets/` 文件挂载，不要把密钥写入 Compose、Git 或扫描结果目录。

```bash
mkdir -p scanner-secrets
printf '%s' "$GITHUB_TOKEN" > scanner-secrets/github_token
printf '%s' "$FOFA_EMAIL" > scanner-secrets/fofa_email
printf '%s' "$FOFA_KEY" > scanner-secrets/fofa_key
chmod 600 scanner-secrets/github_token scanner-secrets/fofa_email scanner-secrets/fofa_key
```

默认文件路径：

```text
/run/secrets/github_token
/run/secrets/fofa_email
/run/secrets/fofa_key
```

也支持直接传入 `GITHUB_TOKEN`、`FOFA_EMAIL`、`FOFA_KEY` 环境变量，但文件挂载更适合生产环境。

GitHub Token 只需要读取公开代码搜索与文件内容所需的最小权限。不要使用具备仓库写入、Actions 管理或部署权限的 Token。

## 配置项

```text
ENABLE_EDGE_INTELLIGENCE=true
EDGE_GITHUB_MAX_QUERIES=10
EDGE_GITHUB_MAX_FILES=80
EDGE_FOFA_MAX_RESULTS=500
EDGE_INTEL_TIMEOUT=12
EDGE_INTEL_MAX_BYTES=1048576
EDGE_INTEL_FEED_SCAN=false
GITHUB_TOKEN_FILE=/run/secrets/github_token
FOFA_EMAIL_FILE=/run/secrets/fofa_email
FOFA_KEY_FILE=/run/secrets/fofa_key
```

GitHub Code Search 默认限制为 10 个平衡查询，按照“裸域名、Actions、Staging、Dev、UAT、Preprod”在多个根域之间轮转，降低单个根域耗尽搜索配额的概率。

缺少 GitHub 或 FOFA 凭据时，模块会记录数据源状态并继续执行，不会中断 Scanner V2。

## 输出文件

| 文件 | 内容 |
|---|---|
| `edge-assets.jsonl` | 关联后的边缘资产、环境、组件、端口、证据和 P0-P3 人工复核优先级 |
| `edge-review.md` | 适合人工阅读的非生产环境与边缘系统清单 |
| `edge-github-files.jsonl` | GitHub 文件分析结果，不包含原始文件正文 |
| `edge-fofa-results.jsonl` | 经过字段裁剪和脱敏的 FOFA 结果 |
| `edge-sensitive-indicators.jsonl` | 敏感配置类型和脱敏证据 |
| `edge-environments.txt` | 环境标签、资产和证据来源 |
| `edge-hosts.txt` | 仍在授权域名/IP 范围内的主机 |
| `edge-urls.txt` | 仍在授权范围内的 HTTP URL |
| `edge-intelligence-stats.json` | 数据源状态和统计数据 |

HTML 总报告及 `summary.json`、`summary.md` 会同步加入边缘系统摘要。

## 建议复核顺序

1. 先确认 DNS、证书、代码仓库归属、部署时间和 FOFA 更新时间。
2. 对 Dev/Staging/Test 环境检查生产密钥复用、测试账号、调试开关、测试数据和访问控制。
3. 对 GitHub Actions 检查环境保护规则、自托管 Runner、部署目标与 Secret 使用范围。
4. 对开发组件检查是否暴露登录面、匿名读取、调试信息或版本信息。
5. 只有确认资产归属后，才加入后续主动验证范围。
