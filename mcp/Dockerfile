FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server.py /app/server.py
COPY enhanced_tools.py /app/enhanced_tools.py
COPY launcher.py /app/launcher.py
COPY patch_server.py /app/patch_server.py

RUN python /app/patch_server.py \
    && python -m py_compile /app/server.py /app/enhanced_tools.py /app/launcher.py \
    && rm -f /app/patch_server.py \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin mcp \
    && mkdir -p /data \
    && chown -R mcp:mcp /app /data

USER mcp

EXPOSE 5013

CMD ["python", "/app/launcher.py"]
