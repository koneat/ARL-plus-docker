FROM golang:1.26-bookworm AS builder

ARG NUCLEI_VERSION=v3.11.0
ARG HTTPX_VERSION=v1.9.0
ARG NAABU_VERSION=v2.6.1
ARG KATANA_VERSION=v1.6.1
ARG SUBFINDER_VERSION=v2.14.0
ARG DNSX_VERSION=v1.2.3
ARG AFROG_VERSION=v3.5.3
ARG FFUF_VERSION=v2.1.0
ARG UNCOVER_VERSION=3f7b74af20b24a7d5477d1dc77f6ba881219b0de

ENV CGO_ENABLED=1 \
    GOBIN=/out

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /out && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} && \
    go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION} && \
    go install github.com/projectdiscovery/uncover/cmd/uncover@${UNCOVER_VERSION} && \
    go install github.com/zan8in/afrog/v3/cmd/afrog@${AFROG_VERSION} && \
    go install github.com/ffuf/ffuf/v2@${FFUF_VERSION}

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq libpcap0.8 python3 nmap tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ /usr/local/bin/
COPY entrypoint.sh run-scan.sh run-scan-uncover.sh prepare_targets.py uncover_assets.py summarize.py /opt/scanner/
COPY wordlists/high-value-paths.txt /opt/scanner/wordlists/high-value-paths.txt

RUN chmod +x \
      /opt/scanner/entrypoint.sh \
      /opt/scanner/run-scan.sh \
      /opt/scanner/run-scan-uncover.sh && \
    mkdir -p /work/results /root/.config /root/nuclei-templates /opt/pocs/nuclei /opt/pocs/afrog /run/secrets

WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/scanner/entrypoint.sh"]
CMD ["sleep", "infinity"]
