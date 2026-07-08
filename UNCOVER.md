# Uncover 多引擎资产聚合

该功能是现有独立扫描链的前置层，不修改 ARL Web、Worker、Scheduler、MongoDB、RabbitMQ 或 MCP。

当配置了搜索引擎凭证后，扫描流程变为：

```text
输入域名
  -> Uncover 查询 FOFA/Hunter/Quake/Shodan/ZoomEye 等来源
  -> 只自动接收同根域名的 Host、URL 和 Host:Port
  -> IP-only 结果默认只保存为待确认候选
  -> 合并到原有 subfinder/dnsx/naabu/httpx/katana/nuclei/afrog/ffuf 链
```

Uncover 未配置、没有结果或执行失败时，原扫描链继续执行，不会阻塞任务。

## 配置凭证

```bash
cd /root/ARL-plus-docker
mkdir -p scanner-secrets
chmod 700 scanner-secrets
cp scanner-secrets/uncover-provider.example.yaml \
  scanner-secrets/uncover-provider.yaml
chmod 600 scanner-secrets/uncover-provider.yaml
```

然后编辑：

```text
scanner-secrets/uncover-provider.yaml
```

只保留并填写实际使用的引擎。不要把真实密钥写入 `.env`、日志或 GitHub；该文件已经被 `.gitignore` 忽略。

## 运行

无需更改原命令：

```bash
bash scripts/scan-enhanced.sh targets.txt standard
```

默认行为：

```dotenv
ENABLE_UNCOVER=true
UNCOVER_ENGINES=auto
UNCOVER_LIMIT=100
UNCOVER_RATE_LIMIT=2
UNCOVER_ACCEPT_IP_ONLY=false
```

`UNCOVER_ENGINES=auto` 会从 provider 配置中自动识别已经配置的引擎。

标准和快速模式每个域名生成一个保守查询；深度模式会增加证书相关查询。

## 限定引擎

```bash
UNCOVER_ENGINES='fofa,hunter,quake' \
  bash scripts/scan-enhanced.sh targets.txt standard
```

## 临时关闭

```bash
ENABLE_UNCOVER=false \
  bash scripts/scan-enhanced.sh targets.txt standard
```

## IP-only 结果

搜索引擎可能返回只有 IP、没有域名归属证据的结果。默认不会自动扫描这些 IP，以免越出域名授权范围；它们保存在：

```text
scan-results/latest/uncover-ip-candidates.txt
scan-results/latest/uncover.candidates.jsonl
```

明确确认这些 IP 均在授权范围后，才能显式开启：

```bash
UNCOVER_ACCEPT_IP_ONLY=true \
  bash scripts/scan-enhanced.sh targets.txt standard
```

## 主要结果

```text
uncover.jsonl                 Uncover 原始统一 JSONL
uncover.scoped.jsonl          自动确认在域名范围内的结果
uncover.candidates.jsonl      未自动并入扫描的候选
uncover-hosts.txt             同根域名资产
uncover-services.txt          同根域名 Host:Port
uncover-urls.txt              同根域名 URL
uncover-ip-candidates.txt     待确认 IP
uncover-stats.json            来源和数量统计
```

最终的 `summary.md` 和 `summary.json` 会显示外部搜索引擎发现数量和来源分布。

## 生产更新

```bash
cd /root/ARL-plus-docker
git fetch origin main
git checkout main
git pull --ff-only origin main

cp scanner-secrets/uncover-provider.example.yaml \
  scanner-secrets/uncover-provider.yaml
chmod 600 scanner-secrets/uncover-provider.yaml

bash scripts/scan-enhanced.sh targets.txt standard
```

首次运行会重新构建独立 Scanner 镜像，但不会重启 ARL 的任何现有容器。
