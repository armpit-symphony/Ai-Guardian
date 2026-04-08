# Operations Guide

## Monitoring

### Health Check

```bash
curl http://localhost:8000/health
# → {"status": "ok", "version": "0.4.0"}
```

### Container Health

```bash
docker compose ps
# ai-guardian   running (healthy)   0.0.0.0:8000->8000/tcp
```

---

## Viewing Logs

### Docker

```bash
docker compose logs -f ai-guardian
docker compose logs --tail=100 ai-guardian
```

### Host (non-Docker)

Logs written to stdout/stderr (capture with your logging infrastructure).

---

## Restart Procedures

### Docker

```bash
# Restart (state preserved)
docker compose restart ai-guardian

# Stop
docker compose stop ai-guardian

# Start
docker compose start ai-guardian

# Full rebuild + restart
docker compose up --build -d
```

### Host (non-Docker)

```bash
# Graceful shutdown: kill the process
pkill -f "python.*ai_guardian"
# or
kill $(cat /tmp/ai_guardian.pid)

# Start
nohup python -m ai_guardian.main > ai_guardian.log 2>&1 &
```

---

## State Verification After Restart

### Verify pending approvals survived restart

```bash
curl http://localhost:8000/api/v1/approvals \
  -H "X-API-Key: $ADMIN_KEY"
# Should return all previously pending approvals with same approval_ids
```

### Verify breakglass sessions

```bash
curl http://localhost:8000/api/v1/breakglass \
  -H "X-API-Key: $ADMIN_KEY"
# Used sessions should still show status=used (cannot be reused)
# Revoked sessions should still show status=revoked
```

### Verify audit log hash chain

```bash
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $ADMIN_KEY"
# → {"valid": true, "errors": []}
```

### Verify audit entries persisted

```bash
curl "http://localhost:8000/api/v1/audit/logs?limit=10" \
  -H "X-API-Key: $ADMIN_KEY"
# Should include all entries from before the restart
```

---

## Database Backup

### SQLite (while running)

```bash
# Host path
cp /path/to/ai_guardian.db /backup/ai_guardian-$(date +%Y%m%d).db

# Docker volume
docker compose exec ai-guardian cp /app/data/ai_guardian.db /tmp/backup.db
docker compose cp ai-guardian:/tmp/backup.db ./backup-$(date +%Y%m%d).db
```

### Verify backup integrity

```bash
sqlite3 /backup/ai_guardian-20260408.db "PRAGMA integrity_check;"
# → ok
```

---

## Database Restore

```bash
# Stop service first
docker compose stop ai-guardian

# Replace DB
cp /backup/ai_guardian-20260408.db /path/to/ai_guardian.db

# Restart
docker compose start ai-guardian

# Verify
curl http://localhost:8000/health
docker compose exec ai-guardian wget -qO- http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $ADMIN_KEY"
```

---

## Viewing Pending Approvals

```bash
# All pending
curl http://localhost:8000/api/v1/approvals \
  -H "X-API-Key: $ADMIN_KEY"

# Specific one
curl http://localhost:8000/api/v1/approvals/apr_abc123... \
  -H "X-API-Key: $ADMIN_KEY"
```

---

## Emergency: Clear All Pending Approvals

```bash
# List all approval IDs
APPROVAL_IDS=$(curl -s http://localhost:8000/api/v1/approvals \
  -H "X-API-Key: $ADMIN_KEY" | jq -r '.[].approval_id')

# Deny each
for id in $APPROVAL_IDS; do
  curl -X POST "http://localhost:8000/api/v1/approvals/$id/decide?decision=deny" \
    -H "X-API-Key: $ADMIN_KEY"
  echo "Denied: $id"
done
```

---

## Troubleshooting

### Service won't start

```bash
# Check logs
docker compose logs ai-guardian

# Common cause: port already in use
ss -tlnp | grep 8000

# Common cause: database locked
docker compose exec ai-guardian sh -c "ls -la /app/data/"
```

### Pending approvals not persisting after restart

Check that the volume is correctly mounted:
```bash
docker compose exec ai-guardian ls -la /app/data/
# Should show ai_guardian.db
```

### Audit verify returns `valid: false`

```bash
# Check errors field for specifics
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $ADMIN_KEY"
# → {"valid": false, "errors": ["Entry 3: broken chain link..."]}
```

If tampered: do NOT reset the database — escalate to security team.

---

## Capacity Planning

| Resource | Default | Configurable |
|---------|---------|-------------|
| Rate limit | 120 req/min/tenant | `AI_GUARDIAN_RATE_LIMIT_PER_MINUTE` |
| DB | SQLite (single file) | `AI_GUARDIAN_DATABASE_URL` |
| Audit log | Unlimited entries | Prune via export + vacuum |
| Breakglass sessions | Unlimited | Cleanup via revoke/expire |

### Audit Log Pruning

Export before a cutoff date, then vacuum:
```bash
curl "http://localhost:8000/api/v1/audit/export?format=json&limit=100000" \
  -H "X-API-Key: $ADMIN_KEY" > audit-backup-$(date +%Y%m%d).json

# Vacuum DB (requires downtime or exclusive lock)
sqlite3 /path/to/ai_guardian.db "DELETE FROM audit_log WHERE id < (SELECT MAX(id) FROM audit_log WHERE timestamp < '2026-01-01')); VACUUM;"
```

---

## Alerting

Configure alerts on:
- `GET /health` returns non-200
- `docker compose ps` shows unhealthy/unhealthy
- Audit verify returns `valid: false`
- Cash balance drops below $15 (for kalshi-bot)
