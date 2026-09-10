# CyberCheck backend - container image.
# Works on AWS App Runner / ECS / Fly.io / Cloud Run / any Docker host.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

EXPOSE 8000
# Respect $PORT if the platform injects one (App Runner, Cloud Run, Fly).
CMD ["sh", "-c", "gunicorn ai_extencion:app --bind 0.0.0.0:${PORT:-8000} --workers 2 --timeout 30"]
