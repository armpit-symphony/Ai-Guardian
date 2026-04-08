# Pilot Deployment Template

This document describes the recommended deployment pattern for pilot users of Ai-Guardian.

---

## Recommended Architecture

```
                        ┌─────────────────┐
  AI Agent ───────────►│   TLS Proxy      │
  (your workload)       │   (Caddy/nginx)  │
                        │   :443           │
                        └────────┬────────┘
                                 │HTTPS
                                 ▼
                        ┌─────────────────┐
                        │  Ai-Guardian     │
                        │  uvicorn         │
                        │  :8000           │
                        └────────┬────────┘
                                 │local
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
            ┌───────────────┐         ┌───────────────┐
            │  SQLite /     │         │  Backup        │
            │  PostgreSQL    │         │  /snapshots    │
            │  (data dir)   │         │  (cron daily)  │
            └───────────────┘         └───────────────┘
```

**Design principle:** Ai-Guardian itself runs HTTP-only on a private port. All external traffic enters through a TLS proxy that terminates HTTPS. This keeps Ai-Guardian simple while meeting production TLS requirements.

---

## Quick-Start (Single Server)

### 1. Install Ai-Guardian

```bash
git clone https://github.com/armpit-symphony/Ai-Guardian.git
cd Ai-Guardian
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Configure environment

```bash
cat > .env << 'EOF'
# REQUIRED
AI_GUARDIAN_BOOTSTRAP_KEYS=change-me-to-a-long-random-string

# Database (SQLite — pilot default)
AI_GUARDIAN_DB_PATH=/app/data/ai_guardian.db

# Optional: PostgreSQL for multi-node or production scale
# AI_GUARDIAN_DATABASE_URL=postgresql://user:pass@localhost:5432/guardian

# Optional: Cross-provider fallback
AI_GUARDIAN_DEFAULT_ROUTE=openai
OPENAI_API_KEY=sk-...
EOF
```

### 3. Create data directory

```bash
sudo mkdir -p /app/data
sudo chown $(whoami) /app/data
```

### 4. Start Ai-Guardian

```bash
# Test run
python -m ai_guardian.main &

# Production: use systemd
sudo cp deploy/ai-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ai-guardian
sudo systemctl start ai-guardian
```

### 5. Configure TLS Proxy

**Option A: Caddy (Recommended — automatic TLS)**

```bash
# /etc/caddy/Caddyfile

your-guardian.example.com {
    reverse_proxy localhost:8000
}
```

```bash
sudo systemctl restart caddy
```

**Option B: Nginx**

```nginx
# /etc/nginx/sites-available/ai-guardian

server {
    listen 443 ssl;
    server_name your-guardian.example.com;

    ssl_certificate /etc/letsencrypt/live/your-guardian.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-guardian.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**⚠️ Important:** Ai-Guardian is HTTP-only by design. Never expose port 8000 directly to the internet. The TLS proxy is required.

---

## Docker Deployment

```bash
# docker-compose.yml
version: '3.8'
services:
  ai-guardian:
    image: ghcr.io/armpit-symphony/ai-guardian:latest
    restart: unless-stopped
    environment:
      AI_GUARDIAN_BOOTSTRAP_KEYS: "${BOOTSTRAP_KEY}"
      AI_GUARDIAN_DB_PATH: /app/data/ai_guardian.db
    volumes:
      - guardian-data:/app/data
    expose:
      - "8000"

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy-data:/data
      - caddy-config:/config
    depends_on:
      - ai-guardian

volumes:
  guardian-data:
  caddy-data:
  caddy-config:
```

```bash
# .env
BOOTSTRAP_KEY=your-long-random-bootstrap-key

# Caddyfile
your-guardian.example.com {
    reverse_proxy ai-guardian:8000
}
```

```bash
docker compose up --build -d
```

---

## Backup Cadence

### SQLite (pilot/default)

**Daily automated backup:**
```bash
# /etc/cron.d/guardian-backup
0 3 * * * root /app/data/guardian_backup.sh

# /app/data/guardian_backup.sh
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
cp /app/data/ai_guardian.db /backups/ai_guardian_${DATE}.db
find /backups -name "ai_guardian_*.db" -mtime +7 -delete
echo "Backup complete: ai_guardian_${DATE}.db" >> /var/log/guardian-backup.log
```

**Restore test (verify weekly):**
```bash
cp /app/data/ai_guardian.db /tmp/ai_guardian_live.db
cp /backups/ai_guardian_20260408_030000.db /app/data/ai_guardian.db
# Restart service
# Verify: GET /api/v1/audit/verify returns valid:true
# Restore live
cp /tmp/ai_guardian_live.db /app/data/ai_guardian.db
```

### PostgreSQL (scaling)

```bash
# Daily pg_dump
0 3 * * * pg_dump -U guardian_user -d ai_guardian > /backups/guardian_$(date +\%Y\%m\%d).sql

# Point-in-time recovery (PITR) — configure from PostgreSQL docs
```

---

## What to Monitor Daily

### Health Check
```bash
curl https://your-guardian.example.com/health
# Expected: {"status": "ok", "version": "..."}
```

### Alert on:
- `GET /health` returns non-200
- `GET /api/v1/audit/verify` returns `valid: false`
- Disk usage > 80%
- Database file hasn't been written to in 24h

### Monitor weekly:
```bash
# Pending approvals accumulating (normal: 0–5)
curl "https://your-guardian.example.com/api/v1/approvals" \
  -H "X-API-Key: $ADMIN_KEY"

# Blocked actions today
curl "https://your-guardian.example.com/api/v1/audit/blocked?limit=10" \
  -H "X-API-Key: $ADMIN_KEY"

# Breakglass events (should be rare)
curl "https://your-guardian.example.com/api/v1/audit/logs?limit=50&decision=allowed" \
  -H "X-API-Key: $ADMIN_KEY" | grep breakglass
```

### Dashboard metrics to track:
- Daily blocked count (watch for spikes → possible misconfiguration or attack)
- Daily pending approvals (watch for approvals that never get decided)
- Breakglass use count (should be very low — if increasing, investigate)
- Audit log growth rate (estimate storage needs)

---

## Security Checklist (Pre-Pilot)

- [ ] Bootstrap key is long and random (`openssl rand -hex 32`)
- [ ] Bootstrap key rotated from default/documented examples
- [ ] Breakglass PIN is known only to on-call personnel (not in this repo)
- [ ] TLS proxy active on port 443 (port 8000 not publicly accessible)
- [ ] Admin API keys stored in secrets manager, not in code
- [ ] Backup directory is on a separate volume from the database
- [ ] Audit log export captured off-box (backup to separate storage)
- [ ] Log rotation configured for Guardian logs
