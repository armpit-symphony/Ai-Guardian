# Quick Start

Get AI Guardian running in under 5 minutes.

---

## 1. Prerequisites

- Python 3.12+ (or Docker)
- A long random bootstrap key (generate with `openssl rand -hex 32`)

---

## 2. Bootstrap Your First Tenant

```bash
export AI_GUARDIAN_BOOTSTRAP_KEYS="your-long-random-key-here"
export AI_GUARDIAN_DB_PATH="/app/data/ai_guardian.db"

python -m ai_guardian.main &
# or: docker compose up --build
```

```bash
# Bootstrap a tenant — returns your first admin API key
curl -X POST http://localhost:8000/api/v1/bootstrap/tenants \
  -H "X-Bootstrap-Key: your-long-random-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "slug": "acme-corp",
    "contact_email": "security@acme.com",
    "plan": "starter"
  }'
```

**Response:**
```json
{
  "tenant": {
    "tenant_id": "ten_a1b2c3d4e5f6",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "contact_email": "security@acme.com",
    "plan": "starter"
  },
  "api_key": "aig_live_abc123...",
  "key_meta": {
    "key_id": "key_...",
    "name": "Primary API key",
    "role": "admin"
  }
}
```

⚠️ **Save `api_key` now — it is not stored and cannot be retrieved.**

---

## 3. Register Your First Agent

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "X-API-Key: aig_live_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "data-pipeline-agent",
    "owner": "data-team",
    "description": "ETL pipeline agent",
    "allowed_domains": ["s3.amazonaws.com", "api.acme.com"]
  }'
```

**Response:** `{"agent_id": "agt_...", ...}` — save this ID.

---

## 3a. Create an Ingest Key (optional, for multi-role testing)

```bash
# Create a restricted ingest key — can submit actions but not approve or view audit
curl -X POST "http://localhost:8000/api/v1/api-keys?name=IngestWorker&role=ingest" \
  -H "X-API-Key: aig_live_abc123..."

# Response: {"api_key": "aig_live_xyz...", "key_meta": {...}}
```

---

## 4. Submit Your First Action

```bash
curl -X POST http://localhost:8000/api/v1/monitor \
  -H "X-API-Key: aig_live_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_...",
    "action": "read_data",
    "context": {"source": "user-request"}
  }'
```

**Allowed response (safe action):**
```json
{
  "decision": "allowed",
  "reason": "Allowed by policy",
  "risk_score": 15,
  "requires_approval": false,
  "breakglass_used": false,
  "approval_id": null,
  "proof": "b264fae6..."
}
```

---

## 5. Submit a High-Risk Action (Triggers Approval Queue)

```bash
curl -X POST http://localhost:8000/api/v1/monitor \
  -H "X-API-Key: aig_live_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_...",
    "action": "http_call",
    "context": {"url": "https://external-api.example.com/data"},
    "source_url": "https://external-api.example.com/data"
  }'
```

**Pending response (requires approval):**
```json
{
  "decision": "pending_approval",
  "reason": "High-risk action (score: 65) requires approval",
  "risk_score": 65,
  "requires_approval": true,
  "breakglass_used": false,
  "approval_id": "apr_abc123...",
  "proof": null
}
```

---

## 6. Approve or Deny

```bash
# List pending approvals
curl http://localhost:8000/api/v1/approvals \
  -H "X-API-Key: aig_live_abc123..."

# Approve (decision in body, not query parameter)
curl -X POST "http://localhost:8000/api/v1/approvals/apr_abc123.../decide" \
  -H "X-API-Key: aig_live_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"decision": "approve"}'

# Deny
curl -X POST "http://localhost:8000/api/v1/approvals/apr_abc123.../decide" \
  -H "X-API-Key: aig_live_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"decision": "deny"}'
```

---

## 7. Verify the Audit Log

```bash
# View recent audit entries
curl http://localhost:8000/api/v1/audit/logs?limit=10 \
  -H "X-API-Key: aig_live_abc123..."

# Verify hash chain integrity
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: aig_live_abc123..."
# → {"valid": true, "errors": []}
```

---

## 8. Breakglass (Emergency Override)

Only for genuine emergencies when the approval queue is too slow.

```bash
# Create breakglass session (PIN required)
curl -X POST http://localhost:8000/api/v1/breakglass \
  -H "X-API-Key: aig_live_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Production data deletion emergency — incident INC-1234"
  }'
# PIN: ai-guardian-breakglass-2026
# reason must be ≥10 characters

# Use breakglass to override a blocked action
curl -X POST "http://localhost:8000/api/v1/breakglass/{breakglass_id}/use?action=delete_all_files" \
  -H "X-API-Key: aig_live_abc123..."

# Revoke when done
curl -X POST "http://localhost:8000/api/v1/breakglass/{breakglass_id}/revoke" \
  -H "X-API-Key: aig_live_abc123..."
```

⚠️ **Each breakglass session can only be used ONCE. After use, it is permanently blocked.**

See [BREAKGLASS_RUNBOOK.md](BREAKGLASS_RUNBOOK.md) for full emergency procedures.

---

## What's Next

- [Deployment guide](DEPLOYMENT.md) — Docker, production configuration
- [API reference](API.md) — All endpoints and schemas
- [Security model](SECURITY_MODEL.md) — How AI Guardian protects your agents
- [Audit taxonomy](AUDIT_TAXONOMY.md) — Understanding audit events
