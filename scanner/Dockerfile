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
ARG URLFINDER_VERSION=ad920f8f07e314b4f242967565601bd77f005947
ARG TLSX_VERSION=d13b67f3068c9c784646b57fed0e8cccb268f0f1
ARG ALTERX_VERSION=bae701c363da0fecf5e788322188df9f4d419bef
ARG CDNCHECK_VERSION=0adc3138f381f86cba14c75f7aa688177167a192
ARG GAU_VERSION=8201b9d1febadba98e9cb81e3f253284e8a4a88b

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
    go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@${URLFINDER_VERSION} && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@${TLSX_VERSION} && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@${ALTERX_VERSION} && \
    go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@${CDNCHECK_VERSION} && \
    go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} && \
    go install github.com/zan8in/afrog/v3/cmd/afrog@${AFROG_VERSION} && \
    go install github.com/ffuf/ffuf/v2@${FFUF_VERSION}

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq libpcap0.8 openssl python3 nmap tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ /usr/local/bin/
COPY \
  entrypoint.sh \
  run-scan.sh \
  run-scan-uncover.sh \
  run-scan-v2.sh \
  run-intelligence.sh \
  run-nuclei-v2.sh \
  run-afrog-v2.sh \
  prepare_targets.py \
  uncover_assets.py \
  extract_api_surface.py \
  asset_intelligence.py \
  sanitize_url_targets.py \
  content_audit.py \
  nuclei_report.py \
  summarize.py \
  enhance_summary.py \
  render_report.py \
  /opt/scanner/
COPY wordlists/ /opt/scanner/wordlists/
COPY V2_VERSION /opt/scanner/V2_VERSION

RUN sed -i 's/-follow-redirects/-follow-host-redirects/g' /opt/scanner/run-scan.sh && \
    chmod +x \
      /opt/scanner/entrypoint.sh \
      /opt/scanner/run-scan.sh \
      /opt/scanner/run-scan-uncover.sh \
      /opt/scanner/run-scan-v2.sh \
      /opt/scanner/run-intelligence.sh \
      /opt/scanner/run-nuclei-v2.sh \
      /opt/scanner/run-afrog-v2.sh && \
    mkdir -p /work/results /root/.config /root/nuclei-templates /opt/pocs/nuclei /opt/pocs/afrog /run/secrets

WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/scanner/entrypoint.sh"]
CMD ["sleep", "infinity"]
