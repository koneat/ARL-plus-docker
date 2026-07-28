ARG ARL_BASE_IMAGE=ki9mu/arl-ki9mu:v3.0.1
FROM ${ARL_BASE_IMAGE}

ARG NUCLEI_VERSION=v3.11.0
ARG AFROG_VERSION=v3.5.3
ARG RAD_VERSION=1.0
ARG INSTALL_CHROMIUM=true
ARG ARL_MERGE_FULL_DOMAIN_WORDLIST=false
ARG WIH_ALLOW_UNVERIFIED_KEYS=false
ARG ARL_FILE_LEAK_MIN_DICTIONARY=40
ARG ARL_NUCLEI_TEMPLATE_MIN_COUNT=50

LABEL org.opencontainers.image.title="ARL Persistent Enhanced Worker" \
      org.opencontainers.image.description="ARL worker with fail-visible Nuclei, pinned official templates, smart wildcard filtering, strict WIH/file-leak quality filtering, automatic Afrog via Chaitin xray, Chromium, libpcap, PySocks, RAD and repository-vendored wordlists"

COPY smart-worker/app/services/wildcardSmart.py /code/app/services/wildcardSmart.py
COPY smart-worker/patch_arl.py /tmp/patch_arl.py
COPY enhanced-worker/patch_worker.py /tmp/patch_worker.py
COPY enhanced-worker/quality_hardening.py /tmp/quality_hardening.py
COPY enhanced-worker/nuclei_scan.py /tmp/nuclei_scan.py
COPY enhanced-worker/afrog_scan.py /tmp/afrog_scan.py
COPY enhanced-worker/high-value-subdomains.txt /tmp/high-value-subdomains.txt
COPY scanner/wordlists/high-value-paths.txt /tmp/high-value-paths.txt
COPY wordlists/vendor/api-endpoints.txt /tmp/vendor-api-endpoints.txt
COPY wordlists/vendor/raft-small-files.txt /tmp/vendor-raft-small-files.txt
COPY wordlists/vendor/subdomains-main.txt /tmp/vendor-subdomains-main.txt
COPY wordlists/vendor/SOURCES.env /tmp/vendor-SOURCES.env
COPY wordlists/vendor/LICENSE.SecLists /tmp/vendor-LICENSE.SecLists
COPY enhanced-worker/afrog-arl /tmp/afrog-arl
COPY enhanced-worker/arl-report-index /tmp/arl-report-index
COPY enhanced-worker/arl-report-index-wrapper /tmp/arl-report-index-wrapper
COPY enhanced-worker/install_tools.sh /tmp/install_tools.sh
COPY enhanced-worker/install_nuclei.sh /tmp/install_nuclei.sh

RUN chmod 0755 /tmp/install_tools.sh /tmp/install_nuclei.sh && \
    AFROG_VERSION="${AFROG_VERSION}" \
    RAD_VERSION="${RAD_VERSION}" \
    INSTALL_CHROMIUM="${INSTALL_CHROMIUM}" \
    ARL_MERGE_FULL_DOMAIN_WORDLIST="${ARL_MERGE_FULL_DOMAIN_WORDLIST}" \
    /tmp/install_tools.sh && \
    NUCLEI_VERSION="${NUCLEI_VERSION}" \
    ARL_NUCLEI_TEMPLATE_DIR=/root/nuclei-templates \
    ARL_NUCLEI_TEMPLATE_MIN_COUNT="${ARL_NUCLEI_TEMPLATE_MIN_COUNT}" \
    /tmp/install_nuclei.sh && \
    WIH_ALLOW_UNVERIFIED_KEYS="${WIH_ALLOW_UNVERIFIED_KEYS}" \
    ARL_FILE_LEAK_MIN_DICTIONARY="${ARL_FILE_LEAK_MIN_DICTIONARY}" \
    python3.6 /tmp/quality_hardening.py && \
    python3.6 -m py_compile /tmp/quality_hardening.py /code/app/services/infoHunter.py /code/app/services/nuclei_scan.py && \
    install -d -m 0755 /usr/local/libexec /var/lib/arl-reports/nuclei && \
    mv /usr/local/bin/arl-report-index /usr/local/libexec/arl-report-index-real && \
    install -m 0755 /tmp/arl-report-index-wrapper /usr/local/bin/arl-report-index && \
    test "$(find /root/nuclei-templates -type f \( -name '*.yaml' -o -name '*.yml' \) | wc -l)" -ge "${ARL_NUCLEI_TEMPLATE_MIN_COUNT}" && \
    rm -f /tmp/quality_hardening.py /tmp/arl-report-index-wrapper /tmp/install_tools.sh /tmp/install_nuclei.sh
