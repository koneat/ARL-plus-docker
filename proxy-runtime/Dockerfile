ARG ARL_BASE_IMAGE=ki9mu/arl-ki9mu:v3.0.1
FROM ${ARL_BASE_IMAGE}

LABEL org.opencontainers.image.title="ARL Proxy Runtime" \
      org.opencontainers.image.description="ARL web and scheduler runtime with persistent PySocks support"

RUN python3.6 -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      'PySocks==1.7.1' && \
    python3.6 -c 'import socks; print("pysocks-runtime-ok")'
