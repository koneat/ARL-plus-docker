# ARL Plus Scanner V2

Scanner V2 是独立扫描容器的大版本增强，默认由 `scripts/scan-enhanced.sh` 启动。它不修改或重启 ARL Web、Worker、Scheduler、MongoDB、RabbitMQ 和 MCP。

## 完整扫描链

```text
授权目标
  → 目标规范化与超大 CIDR 防误扫
  → Uncover 多引擎资产聚合
  → Subfinder / DNSX / Naabu / HTTPX / Katana
  → URLFinder + GAU 历史 URL
  → AlterX 子域名智能排列（standard/deep）
  → TLSX 证书 SAN、TLS 版本、Cipher、JARM
  → CDNCheck CDN / 云 / WAF 分类
  → 新域名 DNS + HTTP 验证与回灌
  → 历史 URL 存活验证
  → 新资产二次 Katana 爬取
  → 新增与历史 JavaScript Sourcemap 二次验证
  → 新资产高价值路径 FFUF 二次枚举
  → 内容级文件泄露验证与 JavaScript 接口提取
  → URL 风险评分和优先级排序
  → Nuclei HTTP / API / Exposure / Network / TLS / DNS 分流
  → Afrog 复核
  → Markdown、JSON、单文件 HTML 报告
```

## 新增工具

| 工具 | 用途 |
|---|---|
| URLFinder | 被动 URL 来源聚合 |
| GAU | Wayback、Common Crawl、OTX、URLScan 历史 URL |
| AlterX | 根据现有子域名模式和环境词表生成高概率排列 |
| TLSX | TLS 证书、SAN、版本、Cipher、JARM |
| CDNCheck | CDN、云平台、WAF 分类 |

这些工具均固定到明确版本或提交，完整镜像构建由 GitHub Actions 验证。

## 1. 原始授权范围固定

Scanner V2 会在基础扫描前保存：

```text
scope-domains.txt
scope-ips.txt
scope-cidrs.txt
```

后续 TLS SAN、AlterX、历史 URL 和 JavaScript 接口提取始终使用最初的根域名判断范围，不会因为中途发现的新名称而自动扩大授权边界。

## 2. 历史 URL 回溯

URLFinder 与 GAU 可发现已经从当前页面、导航和站点地图中消失的：

- 旧 API；
- 测试、预发布和遗留环境；
- 管理入口；
- 带参数接口；
- JavaScript 和 Sourcemap；
- 备份、配置、日志和数据库文件。

历史结果不会直接全部进入漏洞扫描。系统会先执行：

1. 根域范围检查；
2. URL 规范化和去重；
3. 敏感查询参数值清空；
4. 风险评分；
5. 数量截断；
6. HTTP 存活与技术栈验证。

例如：

```text
https://api.example.com/reset?token=historical-secret&id=7
```

会转为：

```text
https://api.example.com/reset?id=7&token=
```

再进行请求，原 Token 不会写入结果或重新发送。

## 3. TLS SAN 资产扩展

TLSX 会从已知域名和开放服务中收集：

- Subject Alternative Name；
- Common Name；
- TLS 版本；
- Cipher；
- JARM；
- 证书异常标志。

只有最初根域名范围内的 SAN 才会进入 DNSX 和 HTTPX 验证。

输出：

```text
tlsx.jsonl
tls-san-domains.txt
tls-findings.jsonl
tls-stats.json
```

## 4. 子域名智能排列

AlterX 根据已经发现的命名模式和内置环境词表生成排列，例如：

```text
api.example.com
api-dev.example.com
api-staging.example.com
dev.api.example.com
internal-api.example.com
```

默认：

- `fast`：关闭；
- `standard`：最多 3,000 个范围内候选；
- `deep`：最多 10,000 个范围内候选。

候选必须属于原始根域，并通过 DNSX 解析后才会回灌。

## 5. 新资产二次验证

基础扫描结束后，新发现资产不会只停留在资产列表。Scanner V2 会继续执行：

- HTTPX 存活和技术栈识别；
- Katana 二次爬取；
- JavaScript `.map` 二次验证；
- 高价值路径 FFUF 二次枚举；
- 内容级验证；
- Nuclei 专项扫描。

主要输出：

```text
enriched-domains.txt
enriched-httpx.jsonl
enriched-live-urls.txt
katana.enriched.txt
sourcemaps.v2.jsonl
sourcemaps.v2.urls.txt
ffuf-v2-hits.txt
```

## 6. 内容级泄露验证

Scanner V2 不再只依赖状态码判断文件泄露。它会对高价值 URL 做限量响应读取，识别：

- `.env` 格式；
- Git HEAD；
- 私钥头；
- SQL Dump；
- Sourcemap；
- Spring 配置；
- 云凭证结构；
- JavaScript 中的 API、Webhook、OAuth 和管理接口；
- 常见 Token 和密钥格式。

安全处理：

- 单响应默认最多读取 1 MiB；
- 不自动跟随 HTTP 跳转；
- 只保留同一授权根域内的绝对接口；
- 支持从 `www.example.com` 提取 `api.example.com`，但拒绝外域；
- 完整密钥不会写入报告，只保留首尾脱敏片段。

输出：

```text
content-audit.jsonl
content-findings.md
content-endpoints.txt
content-audit-stats.json
```

## 7. URL 风险评分

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

## 8. Nuclei 协议分流

Nuclei 分为：

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

默认排除：

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
| 二次 FFUF 目标 | 关闭 | 100 | 300 |
| Sourcemap 二次候选 | 1,000 | 5,000 | 15,000 |
| 最终扫描 URL 上限 | 8,000 | 30,000 | 75,000 |

## 运行

标准：

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

关闭整个 V2 智能增强，使用升级前基础链：

```bash
ENABLE_SCANNER_V2=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

关闭历史 URL：

```bash
ENABLE_PASSIVE_URLS=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

关闭内容读取：

```bash
ENABLE_CONTENT_AUDIT=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

关闭二次 Sourcemap 或 FFUF：

```bash
ENABLE_SOURCEMAP_V2=false \
ENABLE_FFUF_V2=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

强制开启 AlterX：

```bash
ENABLE_ALTERX=true \
ALTERX_LIMIT=5000 \
  bash scripts/scan-enhanced.sh targets.txt standard
```

调整上限：

```bash
PASSIVE_URL_LIMIT=15000 \
CONTENT_AUDIT_LIMIT=800 \
FFUF_V2_MAX_TARGETS=150 \
SOURCEMAP_V2_LIMIT=8000 \
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

## 隔离与资源保护

- Uncover 的纯 IP 默认只进入候选，不自动扫描；
- TLS SAN、AlterX、历史 URL 和 JS 接口必须属于输入根域；
- HTTPX 新阶段只跟随同一主机跳转；
- 内容审计不跟随跳转；
- 每个阶段有数量、并发、速率、超时和响应体大小限制；
- 新阶段失败不会删除或阻断基础扫描结果；
- 不暴露新端口；
- 独立 Compose 项目不加入现有 ARL 网络；
- 容器继续 `cap_drop: ALL` 并启用 `no-new-privileges`。
