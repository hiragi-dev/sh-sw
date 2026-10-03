FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
ENV PYTHONPATH=/srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN printf '#!/bin/sh\nexec python -m app.cli "$@"\n' > /usr/local/bin/shsw-token && chmod +x /usr/local/bin/shsw-token
# プロキシ (uid 1000) が CA 鍵を読めるよう、同じ uid で書き出す
RUN useradd -u 1000 -M -s /usr/sbin/nologin app \
 && mkdir -p /data /certs && chown app:app /data /certs
USER app

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"
# 単一ワーカー: SQLite + プロキシ状態をプロセス内に持つため
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
