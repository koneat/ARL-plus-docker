ARG ARL_BASE_IMAGE=ki9mu/arl-ki9mu:v3.0.1
FROM ${ARL_BASE_IMAGE}

LABEL org.opencontainers.image.title="ARL Smart Wildcard Worker" \
      org.opencontainers.image.description="ARL worker with DNS candidate retention, HTTP fingerprint wildcard verification and persistent SOCKS proxy support"

COPY app/services/wildcardSmart.py /code/app/services/wildcardSmart.py
COPY patch_arl.py /tmp/patch_arl.py

RUN python3.6 -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      'PySocks==1.7.1' && \
    python3.6 /tmp/patch_arl.py && \
    python3.6 -m py_compile \
      /code/app/services/massdns.py \
      /code/app/services/wildcardSmart.py \
      /code/app/tasks/domain.py && \
    python3.6 -c 'import socks; from app.services.wildcardSmart import WildcardSmartFilter' && \
    grep -q 'WildcardSmartFilter' /code/app/tasks/domain.py && \
    ! grep -q 'if ip in self.not_found_domain_ips' /code/app/tasks/domain.py && \
    rm -f /tmp/patch_arl.py
