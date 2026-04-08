# ─────────────────────────────────────────────────────────────
# AI Guardian — Production Dockerfile
# Multi-stage: build → run, minimal attack surface
# ─────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# ── Build stage ──────────────────────────────────────────────────
FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Production stage ────────────────────────────────────────────
FROM base AS production

# Non-root user for safety
RUN groupadd -r guardian && useradd -r -g guardian guardian

COPY --from=builder /install /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application
COPY ai_guardian/ ./ai_guardian/
COPY migrations/  ./migrations/
COPY scripts/    ./scripts/

RUN mkdir -p /app/data && chown guardian:guardian /app/data

USER guardian

# Defaults — can be overridden via env or docker-compose
ENV AI_GUARDIAN_DB_PATH=/app/data/ai_guardian.db
ENV AI_GUARDIAN_BOOTSTRAP_KEYS=
ENV AI_GUARDIAN_RATE_LIMIT_PER_MINUTE=120
ENV PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:${PORT}/health || exit 1

# Run migrations automatically on start, then serve
CMD ["sh", "-c", "python scripts/run_migrations.py && uvicorn ai_guardian.main:app --host 0.0.0.0 --port ${PORT}"]
