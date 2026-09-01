FROM aquasec/trivy:latest AS trivy
FROM python:3.12-slim

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN pip install --no-cache-dir httpx requests

WORKDIR /app
COPY agent.py .
COPY scan.sh .
RUN chmod +x scan.sh

CMD ["python", "-u", "agent.py"]
