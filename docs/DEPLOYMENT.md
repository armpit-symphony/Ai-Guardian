# Deployment Guide

Docker is the recommended deployment method. SQLite is the default database.

---

## Storage Options

| Option | Command | Status |
|--------|---------|--------|
| **SQLite** (default) | `AI_GUARDIAN_DB_PATH=/app/data/ai_guardian.db` | ✅ Verified |
| **PostgreSQL** | `AI_GUARDIAN_DATABASE_URL=postgresql://...` | ⚠️ Methods implemented, not end-to-end tested |

For production multi-instance deployments, use PostgreSQL. For single-instance deployments, SQLite with the `/app/data` volume is sufficient.

---

## Docker Compose (Recommended)

### 1. Configure Environment

```bash
cd Ai-Guardian
cp .env.example .env
```

Edit `.env`:
```bash
AI_GUARDIAN_BOOTSTRAP_KEYS=CHANGE-THIS-TO-A-LONG-RANDOM-STRING
AI_GUARDIAN_RATE_LIMIT_PER_MINUTE=120
AI_GUARDIAN_PORT=8000
AI_GUARDIAN_BLOCKED_DOMAINS=pastebin.com,mega.nz,transfer.sh
AI_GUARDIAN_DEFAULT_ALLOWED_DOMAINS=github.com,api.openai.com,yourdomain.com
```

### 2. Start

```bash
docker compose up --build -d
```

### 3. Verify

```bash
curl http://localhost:8000/health
# → {"status": "ok", "version": "0.4.0"}
```

### 4. Bootstrap First Tenant

```bash
BOOTSTRAP_KEY=$(grep AI_GUARDIAN_BOOTSTRAP_KEYS .env | cut -d= -f2)
curl -X POST http://localhost:8000/api/v1/bootstrap/tenants \
  -H "X-Bootstrap-Key: $BOOTSTRAP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"MyOrg","slug":"my-org","contact_email":"security@myorg.com","plan":"starter"}'
```

### 5. Restart — Verify State Persists

```bash
docker compose restart ai-guardian
sleep 5
curl http://localhost:8000/health
# Pending approvals, breakglass sessions, and audit logs all survive restart ✅
```

---

## Docker (Standalone)

```bash
docker build -t ai-guardian:0.4.0 .

docker run -d \
  --name ai-guardian \
  -p 8000:8000 \
  -v ai_guardian_data:/app/data \
  -e AI_GUARDIAN_BOOTSTRAP_KEYS="your-long-random-key" \
  -e AI_GUARDIAN_DB_PATH=/app/data/ai_guardian.db \
  ai-guardian:0.4.0
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AI_GUARDIAN_BOOTSTRAP_KEYS` | ✅ | — | Comma-separated bootstrap keys |
| `AI_GUARDIAN_DB_PATH` | | `ai_guardian.db` | SQLite file path |
| `AI_GUARDIAN_DATABASE_URL` | | `null` | PostgreSQL connection string (overrides DB_PATH) |
| `AI_GUARDIAN_RATE_LIMIT_PER_MINUTE` | | `120` | Rate limit per tenant |
| `AI_GUARDIAN_BLOCKED_DOMAINS` | | pastebin.com,... | Comma-separated blocked domains |
| `AI_GUARDIAN_DEFAULT_ALLOWED_DOMAINS` | | github.com,... | Comma-separated default allowed domains |
| `AI_GUARDIAN_SUSPICIOUS_PHRASES` | | *(long list)* | Phrases that trigger risk scoring |
| `AI_GUARDIAN_PORT` | | `8000` | Service port |
| `PORT` | | `8000` | Alternative port variable |

---

## Health Check

```bash
curl http://localhost:8000/health
```

Docker HEALTHCHECK already configured:
```
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8000/health || exit 1
```

---

## Database Backup

SQLite: copy the database file (service can stay running — SQLite supports concurrent reads):

```bash
# While service is running:
cp /path/to/ai_guardian.db /backup/ai_guardian-$(date +%Y%m%d-%H%M%S).db

# With Docker volume:
docker compose exec ai-guardian cp /app/data/ai_guardian.db /tmp/backup.db
docker cp ai-guardian:/tmp/backup.db ./ai_guardian-backup.db
```

---

## Upgrading

1. Pull new image / code
2. Migrations run automatically on startup (`scripts/run_migrations.py`)
3. Restart service:
```bash
docker compose restart ai-guardian
```
4. Verify:
```bash
curl http://localhost:8000/health
docker compose exec ai-guardian python -c "from scripts.run_migrations import run_sqlite; run_sqlite('/app/data/ai_guardian.db')"
```

---

## PostgreSQL (Multi-Instance)

```yaml
# docker-compose.yml — uncomment postgres section
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: ai_guardian
      POSTGRES_USER: ai_guardian
      POSTGRES_PASSWORD: CHANGE-ME
    volumes:
      - postgres_data:/var/lib/postgresql/data

  ai-guardian:
    environment:
      AI_GUARDIAN_DATABASE_URL: postgresql://ai_guardian:CHANGE-ME@postgres:5432/ai_guardian
      AI_GUARDIAN_DB_PATH: ""   # empty — use DATABASE_URL
```

⚠️ **PostgreSQL not end-to-end tested in this release.** SQLite is verified.

---

## Production Checklist

- [ ] `AI_GUARDIAN_BOOTSTRAP_KEYS` set to a long random value (not default)
- [ ] Dashboard password set if web UI is exposed
- [ ] TLS termination in front of the service (AI Guardian does not handle TLS)
- [ ] Backup procedure for SQLite file established
- [ ] API keys stored in a secrets manager (not in code)
- [ ] Breakglass PIN rotated from default in production
- [ ] `AI_GUARDIAN_BLOCKED_DOMAINS` reviewed and customized
- [ ] Rate limit configured for your traffic patterns
