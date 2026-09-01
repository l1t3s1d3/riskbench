FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl sqlite3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r riskdesk && useradd -r -g riskdesk -d /app riskdesk

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir python-pptx

COPY app/ app/
COPY .env.example .env.example

RUN mkdir -p /data && chown riskdesk:riskdesk /data

ENV RISKDESK_DB_URL=sqlite:////data/riskdesk.db \
    RISKDESK_HOST=0.0.0.0 \
    RISKDESK_PORT=8080 \
    RISKDESK_SCHEDULER=1

VOLUME /data
EXPOSE 8080

USER riskdesk

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:8080/api/meta || exit 1

ENTRYPOINT ["python", "-m", "app.cli"]
CMD ["serve"]
