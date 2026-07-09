ARG ARL_BASE_IMAGE=ki9mu/arl-ki9mu:v3.0.1
FROM ${ARL_BASE_IMAGE}

ARG AFROG_VERSION=v3.5.3
ARG RAD_VERSION=1.0
ARG INSTALL_CHROMIUM=true
ARG ARL_MERGE_FULL_DOMAIN_WORDLIST=false

LABEL org.opencontainers.image.title="ARL Persistent Enhanced Worker" \
      org.opencontainers.image.description="ARL worker with smart wildcard filtering, robust Nuclei output, Chromium, libpcap, PySocks, Afrog, RAD and repository-vendored wordlists"

COPY smart-worker/app/services/wildcardSmart.py /code/app/services/wildcardSmart.py
COPY smart-worker/patch_arl.py /tmp/patch_arl.py
COPY enhanced-worker/patch_worker.py /tmp/patch_worker.py
COPY enhanced-worker/nuclei_scan.py /tmp/nuclei_scan.py
COPY enhanced-worker/high-value-subdomains.txt /tmp/high-value-subdomains.txt
COPY scanner/wordlists/high-value-paths.txt /tmp/high-value-paths.txt
COPY wordlists/vendor/api-endpoints.txt /tmp/vendor-api-endpoints.txt
COPY wordlists/vendor/raft-small-files.txt /tmp/vendor-raft-small-files.txt
COPY wordlists/vendor/subdomains-main.txt /tmp/vendor-subdomains-main.txt
COPY wordlists/vendor/SOURCES.env /tmp/vendor-SOURCES.env
COPY wordlists/vendor/LICENSE.SecLists /tmp/vendor-LICENSE.SecLists
COPY enhanced-worker/afrog-arl /tmp/afrog-arl
COPY enhanced-worker/arl-report-index /tmp/arl-report-index
COPY enhanced-worker/install_tools.sh /tmp/install_tools.sh

RUN chmod 0755 /tmp/install_tools.sh && \
    AFROG_VERSION="${AFROG_VERSION}" \
    RAD_VERSION="${RAD_VERSION}" \
    INSTALL_CHROMIUM="${INSTALL_CHROMIUM}" \
    ARL_MERGE_FULL_DOMAIN_WORDLIST="${ARL_MERGE_FULL_DOMAIN_WORDLIST}" \
    /tmp/install_tools.sh && \
    rm -f /tmp/install_tools.sh
