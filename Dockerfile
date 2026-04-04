FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ai_guardian ./ai_guardian
COPY demo ./demo
COPY migrations ./migrations
COPY scripts ./scripts
COPY README.md .
COPY ARCHITECTURE.md .

RUN mkdir -p /app/data

ENV AI_GUARDIAN_DB_PATH=/app/data/ai_guardian.db
ENV PORT=8000

EXPOSE 8000

CMD ["sh", "-c", "python scripts/run_migrations.py && uvicorn ai_guardian.main:app --host 0.0.0.0 --port ${PORT}"]
