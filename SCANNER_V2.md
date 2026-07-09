# ARL Plus Scanner V2

Scanner V2 是独立扫描容器的大版本增强，不修改或重启 ARL Web、Worker、Scheduler、MongoDB、RabbitMQ 和 MCP。

## 扫描链

```text
授权目标
  → Uncover 多引擎资产聚合
  → Subfinder / DNSX / Naabu / HTTPX / Katana
  → URLFinder + GAU 历史 URL
  → AlterX 子域名智能排列（standard/deep）
  → TLSX 证书 SAN、TLS 指纹和新域名
  → CDNCheck CDN / 云 / WAF 分类
  → 新域名 DNS + HTTP 回灌
  → 历史 URL 存活验证
  → 新资产二次 Katana 爬取
  → 内容级文件泄露验证与 JavaScript 接口提取
  → URL 风险评分和优先级排序
  → Nuclei HTTP / API / 文件泄露 / 网络 / TLS / DNS 分流
  → afrog / ffuf
  → Markdown、JSON、单文件 HTML 报告
```

## 新增工具

| 工具 | 用途 |
|---|---|
| URLFinder | 被动 URL 来源聚合 |
| GAU | Wayback、Common Crawl、OTX、URLScan 历史 URL |
| AlterX | 根据现有子域名模式生成高概率排列 |
| TLSX | TLS 证书、SAN、版本、Cipher、JARM |
| CDNCheck | CDN、云平台、WAF 分类 |

这些工具均固定到明确提交，完整镜像构建由 GitHub Actions 验证。

## 新增能力

### 1. 历史 URL 回溯

从被动来源发现已经从导航、站点地图和当前页面中消失的：

- 旧 API；
- 测试环境；
- 管理入口；
- 带参数接口；
- JavaScript 和 Sourcemap；
- 备份、配置和日志文件。

历史结果不会直接全部进入漏洞扫描。系统会先做范围检查、风险评分、数量截断和 HTTP 存活验证。

### 2. TLS SAN 资产扩展

TLSX 会从现有域名和开放服务中收集证书 SAN，只接受目标根域名范围内的域名，再进行 DNS 与 HTTP 验证。

输出：

```text
tlsx.jsonl
tls-san-domains.txt
tls-findings.jsonl
tls-stats.json
```

### 3. 子域名智能排列

AlterX 根据已经发现的命名模式生成排列，例如：

```text
api.example.com
api-dev.example.com
api-staging.example.com
dev.api.example.com
```

默认：

- `fast`：关闭；
- `standard`：最多 3,000 个范围内候选；
- `deep`：最多 10,000 个范围内候选。

候选必须通过 DNSX 解析才会回灌。

### 4. 内容级泄露验证

Scanner V2 不再只依赖状态码判断文件泄露。它会对高价值 URL 做限量内容读取，识别：

- `.env` 格式；
- Git HEAD；
- 私钥头；
- SQL Dump；
- Sourcemap；
- Spring 配置；
- 云凭证结构；
- JavaScript 中的 API、Webhook、OAuth 和管理接口；
- 常见 Token 和密钥格式。

完整密钥不会写入报告，只保留首尾脱敏片段。

输出：

```text
content-audit.jsonl
content-findings.md
content-endpoints.txt
content-audit-stats.json
```

### 5. URL 风险评分

URL 会根据以下特征排序：

- 管理、登录、重置密码、内部系统；
- API、GraphQL、RPC、Webhook；
- 上传、导入、导出、下载；
- 支付、订单、钱包、提现、转账；
- 配置、日志、备份、数据库、Sourcemap；
- 参数和敏感参数名；
- JavaScript 和深层路径。

输出：

```text
urls-priority.txt
urls-api.txt
urls-params.txt
urls-sensitive.txt
urls-js.txt
url-intelligence.jsonl
url-intelligence-stats.json
```

### 6. Nuclei 协议分流

Nuclei 现在分为：

```text
nuclei.official.jsonl   官方 HTTP 模板
nuclei.custom.jsonl     自定义模板
nuclei.automatic.jsonl  技术栈自动映射
nuclei.exposure.jsonl   配置、备份、日志和文件泄露
nuclei.api.jsonl        API、GraphQL、Webhook、Swagger/OpenAPI
nuclei.network.jsonl    网络服务与 TLS
nuclei.dns.jsonl        DNS 与接管风险
```

所有结果统一去重到：

```text
nuclei.jsonl
nuclei-findings.md
nuclei-status.json
```

默认仍排除：

```text
dos,fuzz,intrusive,bruteforce
```

## 模式差异

| 能力 | fast | standard | deep |
|---|---:|---:|---:|
| 历史 URL 上限 | 2,000 | 10,000 | 30,000 |
| AlterX | 关闭 | 3,000 | 10,000 |
| 内容审计上限 | 100 | 500 | 1,500 |
| 新资产二次爬取 | 关闭 | 开启 | 开启，深度更高 |
| 最终扫描 URL 上限 | 8,000 | 30,000 | 75,000 |

## 运行

```bash
bash scripts/scan-enhanced.sh targets.txt standard
```

快速：

```bash
bash scripts/scan-enhanced.sh targets.txt fast
```

深度：

```bash
bash scripts/scan-enhanced.sh targets.txt deep
```

## 常用控制项

关闭整个 V2 智能增强，保留旧扫描链：

```bash
ENABLE_SCANNER_V2=false bash scripts/scan-enhanced.sh targets.txt standard
```

关闭历史 URL：

```bash
ENABLE_PASSIVE_URLS=false bash scripts/scan-enhanced.sh targets.txt standard
```

关闭内容读取：

```bash
ENABLE_CONTENT_AUDIT=false bash scripts/scan-enhanced.sh targets.txt standard
```

强制开启 AlterX：

```bash
ENABLE_ALTERX=true ALTERX_LIMIT=5000 \
  bash scripts/scan-enhanced.sh targets.txt standard
```

调整 URL 和内容上限：

```bash
PASSIVE_URL_LIMIT=15000 \
CONTENT_AUDIT_LIMIT=800 \
V2_SCAN_URL_LIMIT=40000 \
  bash scripts/scan-enhanced.sh targets.txt standard
```

关闭网络或 DNS Nuclei：

```bash
ENABLE_NUCLEI_NETWORK=false \
ENABLE_NUCLEI_DNS=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

## 报告

```text
scan-results/latest/summary.md
scan-results/latest/summary.json
scan-results/latest/report.html
scan-results/latest/nuclei-findings.md
scan-results/latest/content-findings.md
```

HTML 报告是单文件，不依赖互联网资源。

## 范围与资源保护

- Uncover 的纯 IP 仍默认只进入候选，不自动扫描；
- TLS SAN、AlterX 和历史 URL 必须属于输入根域名；
- 每个阶段有数量、并发、速率、超时和响应体大小限制；
- 内容审计单响应默认最多读取 1 MiB；
- 新阶段失败不会删除或阻断旧扫描结果；
- 不暴露新端口；
- 容器继续丢弃全部 Linux capabilities，并启用 `no-new-privileges`。
