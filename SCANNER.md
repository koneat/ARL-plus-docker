# ARL-plus 独立扫描增强链（Scanner V2）

该功能只增强扫描能力，不替换或修改现有 ARL Web、Worker、Scheduler、MongoDB、RabbitMQ 和 MCP。

扫描容器通过独立 Compose 项目运行，不加入现有 ARL 容器网络，不暴露端口，也不会执行 `docker compose down`。

更完整的架构、参数和输出说明见 [`SCANNER_V2.md`](SCANNER_V2.md)。

## 默认扫描流程

```text
授权目标规范化与超大 CIDR 防误扫
  → Uncover 多引擎资产聚合
  → Subfinder 被动子域名收集
  → DNSX 解析
  → Naabu TCP connect 端口与服务版本发现
  → HTTPX 存活、标题、技术栈、CDN/WAF 探测
  → Katana URL、JavaScript 与已知文件爬取
  → URLFinder + GAU 历史 URL 回溯
  → AlterX 高概率子域名排列（standard/deep）
  → TLSX 证书 SAN、TLS 版本、Cipher、JARM
  → CDNCheck CDN、云平台和 WAF 分类
  → 新域名 DNS/HTTP 验证与资产回灌
  → 历史 URL 存活验证
  → 新资产二次 Katana 爬取
  → 新增/历史 JavaScript Sourcemap 二次验证
  → 新资产高价值路径 FFUF 二次枚举
  → 内容级泄露验证与 JavaScript 接口提取
  → URL 风险评分和优先级排序
  → Nuclei HTTP/API/Exposure/Network/TLS/DNS 分流
  → Afrog 复核
  → Markdown、JSON、单文件 HTML 报告
```

## 使用

准备目标文件，例如 `targets.txt`：

```text
example.com
https://api.example.com/
192.0.2.10
192.0.2.0/24
```

运行标准模式：

```bash
bash scripts/scan-enhanced.sh targets.txt standard
```

扫描结果保存在：

```text
scan-results/<扫描时间>/
```

最近一次扫描：

```text
scan-results/latest/summary.md
scan-results/latest/report.html
```

## 三种模式

### fast

- 常用 100 端口；
- 不做服务版本探测；
- Katana 深度 2；
- 历史 URL 上限 2,000；
- 内容审计上限 100；
- 关闭 AlterX、二次爬取和二次 FFUF；
- 最终扫描 URL 上限 8,000；
- Nuclei/Afrog 以 High、Critical 为主。

### standard

- 常用 1,000 端口；
- Naabu 轻量服务版本识别；
- Katana 深度 3；
- 历史 URL 上限 10,000；
- AlterX 候选上限 3,000；
- 内容审计上限 500；
- 新资产二次爬取、Sourcemap 和 FFUF；
- 最终扫描 URL 上限 30,000；
- Nuclei/Afrog 扫描 Medium、High、Critical。

### deep

- 常用 1,000 端口；
- Naabu 轻量服务版本识别；
- Subfinder 启用全部和递归数据源；
- Katana 主链深度 5，二次爬取深度 4；
- 历史 URL 上限 30,000；
- AlterX 候选上限 10,000；
- 内容审计上限 1,500；
- 二次 FFUF 目标上限 300；
- 最终扫描 URL 上限 75,000；
- Nuclei/Afrog 包含 Low。

三个模式都不会默认执行全端口扫描。确有授权需求时可显式指定：

```bash
CUSTOM_PORTS='80,443,8080,8443,9000-9100' \
  bash scripts/scan-enhanced.sh targets.txt deep
```

## 资产范围保护

Scanner V2 始终保留最初输入的根域名作为授权边界：

- Uncover 的纯 IP 默认只进入候选，不自动扫描；
- TLS SAN、AlterX、历史 URL 和 JavaScript 接口必须属于输入根域；
- AlterX 候选必须通过 DNSX 才能回灌；
- 新域名必须通过 HTTPX 才进入存活目标；
- HTTPX 只跟随同一主机跳转；
- 内容审计不自动跟随 HTTP 跳转；
- 历史 URL 中 Token、密码、签名等敏感查询值会先清空，再进行验证；
- 疑似密钥仅在报告中保存脱敏首尾片段。

## 超大 CIDR 防误扫

默认最多接受：

```dotenv
MAX_IPV4_CIDR_ADDRESSES=4096
MAX_IPV6_CIDR_ADDRESSES=256
```

超过限制的网段会写入 `rejected.txt`，不会进入端口扫描。明确确认范围后才能显式放开：

```bash
ALLOW_LARGE_CIDR=true \
  bash scripts/scan-enhanced.sh targets.txt deep
```

## 默认限速

```dotenv
NAABU_RATE=500
HTTPX_RATE_LIMIT=150
NUCLEI_RATE_LIMIT=120
FFUF_RATE=50
FFUF_V2_RATE=50
SOURCEMAP_V2_RATE_LIMIT=60
```

覆盖示例：

```bash
NUCLEI_RATE_LIMIT=60 \
FFUF_RATE=20 \
FFUF_V2_RATE=20 \
  bash scripts/scan-enhanced.sh targets.txt standard
```

## 单独关闭阶段

```bash
ENABLE_SCANNER_V2=false
ENABLE_SUBFINDER=false
ENABLE_UNCOVER=false
ENABLE_NAABU=false
ENABLE_KATANA=false
ENABLE_SOURCEMAP=false
ENABLE_PASSIVE_URLS=false
ENABLE_ALTERX=false
ENABLE_TLSX=false
ENABLE_CDNCHECK=false
ENABLE_SECONDARY_CRAWL=false
ENABLE_SOURCEMAP_V2=false
ENABLE_FFUF_V2=false
ENABLE_CONTENT_AUDIT=false
ENABLE_NUCLEI=false
ENABLE_AFROG=false
ENABLE_FFUF=false
```

例如，只关闭内容读取：

```bash
ENABLE_CONTENT_AUDIT=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

回退到升级前的稳定扫描链：

```bash
ENABLE_SCANNER_V2=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

## Nuclei 分流

```text
nuclei.official.jsonl   官方 HTTP 模板
nuclei.custom.jsonl     自定义模板
nuclei.automatic.jsonl  技术栈自动映射
nuclei.exposure.jsonl   配置、备份、日志和文件泄露
nuclei.api.jsonl        API、GraphQL、Webhook、Swagger/OpenAPI
nuclei.network.jsonl    网络服务与 TLS
nuclei.dns.jsonl        DNS 与接管风险
```

默认排除：

```text
dos,fuzz,intrusive,bruteforce
```

所有 Nuclei 结果统一去重到：

```text
nuclei.jsonl
nuclei-findings.md
nuclei-status.json
```

## 自定义 PoC

Nuclei 模板放入：

```text
scanner-pocs/nuclei/
```

Afrog 模板放入：

```text
scanner-pocs/afrog/
```

现有 ARL-NPoC 的 PoC 格式与 Nuclei/Afrog 不同，不要直接混用。

Nuclei 3.11 起，使用 JavaScript 协议的自定义模板必须完成签名，否则 Nuclei 会跳过该模板。纯 HTTP/Flow 模板不受此项影响。

## 主要结果文件

```text
targets.normalized.txt        规范化目标
scope-domains.txt             最初授权根域名
rejected.txt                  无效目标和被拦截的超大 CIDR
subfinder.txt                 被动发现的子域名
dnsx.jsonl                    DNS 解析结果
naabu.jsonl                   开放端口与服务探测结果
open-services.txt             host:port 服务目标
httpx.jsonl                   HTTP 站点和指纹
live-urls.txt                 存活 URL
urlfinder.txt                 URLFinder 历史 URL
gau.txt                       GAU 历史 URL
alterx.scoped.txt             范围内子域名排列
tlsx.jsonl                    TLS 数据
tls-san-domains.txt           范围内证书 SAN 域名
cdncheck.jsonl                CDN、云和 WAF 分类
katana.txt                    主链爬取 URL
katana.enriched.txt           新资产二次爬取 URL
sourcemaps.jsonl              所有 Sourcemap 命中
sourcemaps.v2.urls.txt        二次 Sourcemap 命中 URL
ffuf/                         FFUF 原始 JSON
ffuf-v2-hits.txt              新资产二次 FFUF 命中
urls-priority.txt             风险排序后的优先 URL
urls-api.txt                  API/GraphQL/Webhook/RPC URL
urls-params.txt               带参数 URL，敏感值已清空
urls-sensitive.txt            配置、备份、日志、源码等 URL
content-audit.jsonl           内容级验证机器结果
content-findings.md           内容级验证中文报告
content-endpoints.txt         JavaScript 提取的范围内接口
nuclei.jsonl                  去重后的 Nuclei 结果
nuclei-findings.md            Nuclei 中文详情
summary.json                  机器可读汇总
summary.md                    中文汇总
report.html                   单文件 HTML 总报告
errors.log                    失败但未中断的扫描阶段
manifest.txt                  模式、策略、工具和限制清单
```

## 更新扫描镜像

工具版本通过 `docker-compose.scanner.yml` 的构建参数固定。修改版本后重新构建：

```bash
docker compose \
  --project-name arl-plus-scanner \
  -f docker-compose.scanner.yml \
  --profile scanner \
  build --no-cache scanner
```
