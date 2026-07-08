# Nuclei 结果显示与扫描策略

本增强不修改 ARL Web、Worker、MongoDB、RabbitMQ 或 MCP，只增强独立 Scanner。

## 修复的问题

旧流程使用：

```text
-silent -jsonl -o nuclei.*.jsonl
```

结果被写入文件，但终端不展示；`summary.md` 也只显示严重级别数量，不显示模板名称和命中 URL。模板目录为空时，同样只会表现为“没有结果”，不容易判断是没有漏洞还是模板没有加载。

现在会生成：

```text
nuclei.jsonl                  去重后的完整 JSONL
nuclei-findings.md            可直接阅读的详细结果
nuclei-status.json            来源、严重级别、重复和解析错误统计
nuclei-template-status.txt    模板目录和模板数量
nuclei.automatic.log          技术栈自动策略日志
nuclei.exposure.log           文件泄露专项日志
nuclei.api.log                API/HTTP/Webhook 专项日志
```

默认还会在终端打印前 30 条 Nuclei 命中。

## 默认策略

```dotenv
NUCLEI_POLICY=auto
NUCLEI_SHOW_FINDINGS=true
NUCLEI_REPORT_LIMIT=100
NUCLEI_EXCLUDE_TAGS=dos,fuzz,intrusive,bruteforce
ENABLE_NUCLEI_AUTOMATIC=true
ENABLE_NUCLEI_EXPOSURE=true
ENABLE_NUCLEI_API=true
```

`auto` 会根据扫描模式选择：

| 扫描模式 | 策略 | 技术栈自动扫描 | 文件泄露专项 | API 调用面专项 |
|---|---|---:|---:|---:|
| fast | safe | 否 | 是 | 是 |
| standard | balanced | 是 | 是 | 是 |
| deep | deep | 是 | 是 | 是 |

支持显式策略：

```text
off
safe
balanced
exposure
deep
```

示例：

```bash
NUCLEI_POLICY=safe bash scripts/scan-enhanced.sh targets.txt standard
```

临时关闭额外策略，但保留原有 Nuclei 官方和自定义模板扫描：

```bash
NUCLEI_POLICY=off bash scripts/scan-enhanced.sh targets.txt standard
```

## 文件泄露与错误配置专项

默认标签：

```dotenv
NUCLEI_EXPOSURE_TAGS=exposure,config,files,backup,token,logs,debug,misconfig
```

该专项会包括大量严重级别为 `info` 或 `low` 的真实暴露模板，因此使用：

```dotenv
NUCLEI_EXTRA_SEVERITY=info,low,medium,high,critical
```

高价值路径字典也已扩展，覆盖：

- `.env` 多环境和备份变体；
- Git/SVN/Hg 元数据；
- Spring、Laravel、Django、ASP.NET、WordPress、Drupal 配置；
- AWS、GCP、Azure、Terraform、Kubernetes、Helm、Serverless 配置；
- SQL、ZIP、TAR、日志和源码备份；
- Swagger、OpenAPI、GraphQL、Actuator；
- Webhook、Callback、OAuth 回调和 RPC 入口。

## API/HTTP/Webhook 调用面

扫描后会从存活 URL 和 Katana 结果中提取：

```text
api-endpoints.txt
api-docs-endpoints.txt
webhook-endpoints.txt
websocket-endpoints.txt
js-files.txt
api-surface-stats.json
```

默认专项标签：

```dotenv
NUCLEI_API_TAGS=api,swagger,openapi,graphql,webhook
```

这里将用户输入中的“WIH 调用”按 API/HTTP/Webhook 调用面处理。如果实际指的是某个特定工具或协议，只需要替换对应标签和提取规则，不影响现有流程。

## 模板自检

扫描开始前会统计：

```text
/root/nuclei-templates
```

如果模板少于 50 个，会自动尝试：

```bash
nuclei -ut
```

仍然为 0 时会明确打印警告并写入：

```text
nuclei-template-status.txt
nuclei-template-update.log
```

## 查看结果

```bash
cat scan-results/latest/nuclei-findings.md
jq . scan-results/latest/nuclei-status.json
cat scan-results/latest/nuclei-template-status.txt
cat scan-results/latest/summary.md
```

只看严重结果：

```bash
jq -r 'select(._normalized.severity == "critical" or ._normalized.severity == "high") | [._normalized.severity, ._normalized.template_id, ._normalized.matched_at] | @tsv' \
  scan-results/latest/nuclei.jsonl
```

## 生产更新

```bash
cd /root/ARL-plus-docker
git fetch origin main
git checkout main
git pull --ff-only origin main

bash scripts/scan-enhanced.sh targets.txt standard
```

首次运行会重建独立 Scanner 镜像，不会重启现有 ARL 容器。
