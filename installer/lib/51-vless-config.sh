generate_xray_core_config() {
  python3 - "$VLESS_NODES_FILE" "$XRAY_CORE_CONFIG" "$DOCKER_GATEWAY" "$XRAY_SOCKS_PORT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

nodes_file = Path(sys.argv[1])
config_file = Path(sys.argv[2])
listen_ip = sys.argv[3]
listen_port = int(sys.argv[4])

outbounds = []
tags = []

for index, line in enumerate(nodes_file.read_text(encoding="utf-8").splitlines(), 1):
    link = line.strip()
    if not link:
        continue

    parsed = urlsplit(link)
    query = parse_qs(parsed.query)
    host_header = query.get("host", [""])[0]
    path = query.get("path", ["/"])[0]
    security = query.get("security", ["none"])[0]
    encryption = query.get("encryption", ["none"])[0]

    tag = f"proxy-{index}"
    tags.append(tag)

    stream_settings = {
        "network": "ws",
        "security": security,
        "wsSettings": {
            "path": path,
            "headers": {"Host": host_header},
        },
    }
    if security == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": host_header or parsed.hostname,
            "allowInsecure": False,
        }

    outbounds.append(
        {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": parsed.hostname,
                        "port": parsed.port,
                        "users": [
                            {
                                "id": parsed.username,
                                "encryption": encryption,
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream_settings,
            "mux": {"enabled": False},
        }
    )

if not outbounds:
    raise SystemExit("没有可用 VLESS 节点")

config = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "tag": "socks-in",
            "listen": listen_ip,
            "port": listen_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
            },
        }
    ],
    "outbounds": outbounds,
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "network": "tcp,udp",
                "balancerTag": "proxy-pool",
            }
        ],
        "balancers": [
            {
                "tag": "proxy-pool",
                "selector": tags,
                "strategy": {"type": "random"},
            }
        ],
    },
}

config_file.parent.mkdir(parents=True, exist_ok=True)
config_file.write_text(
    json.dumps(config, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
print(f"[OK] Xray-core 配置已生成，出站节点：{len(outbounds)}")
PY
  chmod 0644 "$XRAY_CORE_CONFIG"
}
