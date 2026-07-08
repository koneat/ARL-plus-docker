# ARL-plus 独立扫描增强链

该功能只增强扫描能力，不替换或修改现有 ARL Web、Worker、Scheduler、MongoDB、RabbitMQ 和 MCP。

扫描容器通过独立 Compose 项目运行，不加入现有 ARL 容器网络，不暴露端口，也不会执行 `docker compose down`。

## 扫描流程

```text
目标规范化与超大 CIDR 防误扫
  -> subfinder 被动子域名收集
  -> dnsx DNS 解析
  -> naabu TCP connect 端口与服务版本发现
  -> httpx HTTP 存活、标题、技术栈、CDN 探测
  -> katana URL、JS、已知文件爬取
  -> JavaScript Sourcemap 泄露探测
  -> nuclei 官方模板与自定义模板扫描
  -> afrog PoC 复核
  -> ffuf 高价值配置和备份文件探测
  -> summary.md / summary.json 汇总
```

## 使用

准备目标文件，例如 `targets.txt`：

```text
example.com
https://api.example.com/
192.0.2.10
```

运行标准模式：

```bash
bash scripts/scan-enhanced.sh targets.txt standard
```

扫描结果保存在：

```text
scan-results/<扫描时间>/
```

最近一次扫描可以从以下路径查看：

```text
scan-results/latest/summary.md
```

## 三种模式

### fast

- 常用 100 端口
- 不做服务版本探测
- Katana 深度 2
- Nuclei/afrog 仅 High、Critical
- 默认不运行 ffuf

### standard

- 常用 1000 端口
- Naabu 轻量服务版本识别
- Katana 深度 3，并分析 JS 和已知文件
- Sourcemap 泄露探测
- Nuclei/afrog 扫描 Medium、High、Critical
- 运行高价值路径 ffuf

### deep

- 常用 1000 端口
- Naabu 轻量服务版本识别
- Subfinder 启用全部和递归数据源
- Katana 深度 5
- Sourcemap 泄露探测
- Nuclei/afrog 包含 Low
- 运行高价值路径 ffuf

为了避免误操作，三个模式都不会默认执行全端口扫描。确有授权需求时可显式指定：

```bash
CUSTOM_PORTS='80,443,8080,8443,9000-9100' \
  bash scripts/scan-enhanced.sh targets.txt deep
```

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

## 限速

默认值：

```dotenv
NAABU_RATE=500
HTTPX_RATE_LIMIT=150
NUCLEI_RATE_LIMIT=120
FFUF_RATE=50
FFUF_MAX_TARGETS=100
```

可在命令前覆盖：

```bash
NUCLEI_RATE_LIMIT=60 FFUF_RATE=20 \
  bash scripts/scan-enhanced.sh targets.txt standard
```

## 单独关闭某个阶段

```bash
ENABLE_SUBFINDER=false
ENABLE_NAABU=false
ENABLE_KATANA=false
ENABLE_SOURCEMAP=false
ENABLE_NUCLEI=false
ENABLE_AFROG=false
ENABLE_FFUF=false
```

例如：

```bash
ENABLE_AFROG=false bash scripts/scan-enhanced.sh targets.txt standard
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
targets.normalized.txt    规范化目标
rejected.txt              无效目标和被拦截的超大 CIDR
subfinder.txt             被动发现的子域名
dnsx.jsonl                DNS 解析结果
naabu.jsonl               开放端口与服务探测结果
open-services.txt         可继续交给 HTTP 探测的 host:port
httpx.jsonl               HTTP 站点和指纹
live-urls.txt             存活 URL
katana.txt                爬取 URL
sourcemaps.jsonl          可访问的 JavaScript Sourcemap
nuclei.jsonl              Nuclei 结果
afrog.json                Afrog 结果
ffuf/                     高价值路径结果
summary.json              机器可读汇总
summary.md                中文汇总
errors.log                失败但未中断的扫描阶段
```

## 更新工具版本

工具版本通过 `docker-compose.scanner.yml` 的构建参数固定。修改版本后重新构建：

```bash
docker compose \
  --project-name arl-plus-scanner \
  -f docker-compose.scanner.yml \
  --profile scanner \
  build --no-cache scanner
```
