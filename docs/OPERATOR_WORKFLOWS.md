# Operator Workflows

Step-by-step procedures for common operations.

---

## 1. Bootstrap a New Tenant

```bash
# Generate a bootstrap key
BOOTSTRAP_KEY=$(openssl rand -hex 32)
echo "Bootstrap key: $BOOTSTRAP_KEY"

# Add to .env
echo "AI_GUARDIAN_BOOTSTRAP_KEYS=$BOOTSTRAP_KEY" >> .env

# Create tenant
curl -X POST http://localhost:8000/api/v1/bootstrap/tenants \
  -H "X-Bootstrap-Key: $BOOTSTRAP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "slug": "acme-corp",
    "contact_email": "security@acme.com",
    "plan": "starter"
  }'
```

**Save the returned `api_key` now — it cannot be retrieved later.**

---

## 2. Create API Keys

```bash
# Admin key (full access)
curl -X POST "http://localhost:8000/api/v1/api-keys?name=On-Call+Admin&role=admin" \
  -H "X-API-Key: $ADMIN_KEY"

# Ingest key (can submit actions, cannot approve)
curl -X POST "http://localhost:8000/api/v1/api-keys?name=PipelineAgent&role=ingest" \
  -H "X-API-Key: $ADMIN_KEY"

# Viewer key (can view audit logs only)
curl -X POST "http://localhost:8000/api/v1/api-keys?name=Auditor&role=viewer" \
  -H "X-API-Key: $ADMIN_KEY"
```

---

## 3. Register an Agent

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "data-pipeline-agent",
    "owner": "data-engineering",
    "description": "S3 to BigQuery ETL pipeline",
    "allowed_domains": ["s3.amazonaws.com", "bigquery.googleapis.com"]
  }'
```

Save the returned `agent_id`.

---

## 4. Ingest Submits a Risky Action

```bash
# Ingest submits an external API call (triggers approval queue)
curl -X POST http://localhost:8000/api/v1/monitor \
  -H "X-API-Key: $INGEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_a1b2c3d4",
    "action": "http_call",
    "context": {"url": "https://api.vendor.com/customers/export"}
  }'
```

**Expected response:** `decision: "pending_approval"` with an `approval_id`.

---

## 5. Admin Approves or Denies

```bash
# List pending approvals
curl http://localhost:8000/api/v1/approvals \
  -H "X-API-Key: $ADMIN_KEY"

# Approve
curl -X POST "http://localhost:8000/api/v1/approvals/apr_abc123.../decide?decision=approve" \
  -H "X-API-Key: $ADMIN_KEY"

# Deny
curl -X POST "http://localhost:8000/api/v1/approvals/apr_abc123.../decide?decision=deny" \
  -H "X-API-Key: $ADMIN_KEY"
```

---

## 6. Viewer Views Audit Logs

```bash
# View recent audit entries
curl "http://localhost:8000/api/v1/audit/logs?limit=50" \
  -H "X-API-Key: $VIEWER_KEY"

# Verify hash chain integrity
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $VIEWER_KEY"
```

---

## 7. Blocked Critical Action (No Override Without Breakglass)

```bash
# Agent tries to delete all files (blocked by Step 0)
curl -X POST http://localhost:8000/api/v1/monitor \
  -H "X-API-Key: $INGEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_a1b2c3d4",
    "action": "delete_all_files"
  }'
```

**Expected response:**
```json
{
  "decision": "blocked",
  "reason": "Critical action 'delete_all_files' is blocked",
  "risk_score": 100
}
```

This cannot be approved via the normal queue. Breakglass is required.

---

## 8. Breakglass Lifecycle

```bash
# 8a. Create breakglass (PIN required)
BG_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/breakglass \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "X-Breakglass-Pin: ai-guardian-breakglass-2026" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Production emergency — isolating compromised system NOW"}')
BG_ID=$(echo $BG_RESPONSE | jq -r '.breakglass_id')

# 8b. Use breakglass to override the blocked action
curl -X POST "http://localhost:8000/api/v1/breakglass/$BG_ID/use?action=delete_all_files" \
  -H "X-API-Key: $ADMIN_KEY"

# 8c. Verify it's now blocked (one-time use)
curl -X POST "http://localhost:8000/api/v1/breakglass/$BG_ID/use?action=delete_all_files" \
  -H "X-API-Key: $ADMIN_KEY"
# → 400: "Breakglass session has already been used"

# 8d. Create a separate session and revoke it
BG2=$(curl -s -X POST http://localhost:8000/api/v1/breakglass \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "X-Breakglass-Pin: ai-guardian-breakglass-2026" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Testing revoke functionality"}')
BG2_ID=$(echo $BG2 | jq -r '.breakglass_id')

curl -X POST "http://localhost:8000/api/v1/breakglass/$BG2_ID/revoke" \
  -H "X-API-Key: $ADMIN_KEY"
# → 200: revoked

# 8e. Attempt to use revoked session (should fail)
curl -X POST "http://localhost:8000/api/v1/breakglass/$BG2_ID/use?action=delete_all_files" \
  -H "X-API-Key: $ADMIN_KEY"
# → 400: "Breakglass session is revoked"
```

---

## 9. Audit Verification + Export

```bash
# Verify hash chain
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $ADMIN_KEY"

# Export full audit log
curl "http://localhost:8000/api/v1/audit/export?format=json" \
  -H "X-API-Key: $ADMIN_KEY" \
  > audit-$(date +%Y%m%d).json

# View only guardian decisions
curl "http://localhost:8000/api/v1/audit/logs?limit=100" \
  -H "X-API-Key: $ADMIN_KEY" \
  | jq '[.[] | select(.action | startswith("guardian"))]'

# View only breakglass events
curl "http://localhost:8000/api/v1/audit/logs?limit=100" \
  -H "X-API-Key: $ADMIN_KEY" \
  | jq '[.[] | select(.action | startswith("breakglass"))]'
```

---

## 10. Restart Verification Checklist

After any restart:

```bash
# 1. Health check
curl http://localhost:8000/health

# 2. Pending approvals still present
curl http://localhost:8000/api/v1/approvals \
  -H "X-API-Key: $ADMIN_KEY"

# 3. Breakglass used/revoked state preserved
curl http://localhost:8000/api/v1/breakglass \
  -H "X-API-Key: $ADMIN_KEY"

# 4. Audit log hash chain intact
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $ADMIN_KEY"

# 5. Audit entries persisted
COUNT=$(curl -s "http://localhost:8000/api/v1/audit/logs?limit=1" \
  -H "X-API-Key: $ADMIN_KEY" | jq length)
echo "Audit entries: $COUNT"
```

All should return healthy responses. `audit/verify` must return `valid: true`.
