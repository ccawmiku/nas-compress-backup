FROM node:24-bookworm-slim AS web
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.source="https://github.com/ccawmiku/nas-compress-backup"
LABEL org.opencontainers.image.description="Task-based NAS encrypted incremental backup with PAR2 and CloudDrive2"
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends par2 curl xz-utils ca-certificates \
    && curl -fSL --retry 3 https://github.com/ip7z/7zip/releases/download/26.05/7z2605-linux-x64.tar.xz -o /tmp/7zip.tar.xz \
    && echo "22cf82fcc6eb7474f1d5bb4f02c0f8ebd573a718089d6833dc30f8350a3b232e  /tmp/7zip.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/7zip.tar.xz -C /usr/local/bin 7zz \
    && chmod 755 /usr/local/bin/7zz \
    && rm -f /tmp/7zip.tar.xz && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY scripts/generate_proto.py ./scripts/generate_proto.py
RUN python scripts/generate_proto.py
COPY --from=web /web/dist ./frontend/dist
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 NCB_STATIC=/app/frontend/dist
EXPOSE 19880
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:19880/api/health',timeout=4)"
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","19880","--no-access-log"]

