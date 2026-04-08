# API Reference

Base URL: `http://localhost:8000/api/v1` (or your deployed URL)

**Auth:** All endpoints require `X-API-Key: {key}` header unless marked *(bootstrap)*.

---

## Auth Header

```
X-API-Key: aig_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Role is embedded in the key. Keys are scoped to a tenant.

---

## Endpoints

### Health Check

```
GET /health
```
No auth required.

**Response `200`:**
```json
{"status": "ok", "version": "0.4.0"}
```

---

### Operational Status

```
GET /api/v1/status
```
**Roles:** admin

Returns operational status: queue depth, block counts, breakglass state, audit integrity.

**Response `200`:**
```json
{
  "pending_approvals": 3,
  "blocked_today": 12,
  "breakglass_active": 1,
  "audit_integrity_valid": true,
  "audit_errors": [],
  "active_breakglass_sessions": [
    {"breakglass_id": "bg_abc...", "expires_at": "2026-04-08T22:30:00Z"}
  ]
}
```

### Audit Log

```
GET /api/v1/audit/logs?limit={100}&decision={allowed|blocked|pending_approval}
```
**Roles:** admin, viewer

Returns hash-chained audit entries for your tenant, newest first.
Use `?decision=blocked` to see only blocked actions, `?decision=allowed` for allowed, etc.

```
GET /api/v1/audit/blocked?limit={100}
```
**Roles:** admin, viewer

Shortcut for `?decision=blocked` — returns all blocked actions.

---
```
GET /api/v1/audit/verify
```
**Roles:** admin

Verifies hash chain integrity.

---
### Bootstrap Tenant *(bootstrap — no X-API-Key)*

```
POST /api/v1/bootstrap/tenants
Header: X-Bootstrap-Key: {bootstrap_key_from_env}
Content-Type: application/json

{
  "name": "Acme Corp",
  "slug": "acme-corp",       # unique per deployment
  "contact_email": "security@acme.com",
  "plan": "starter"          // "starter" | "growth" | "enterprise"
}
```

**Response `200`:**
```json
{
  "tenant": {
    "tenant_id": "ten_a1b2c3d4e5f6",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "contact_email": "security@acme.com",
    "plan": "starter"
  },
  "api_key": "aig_live_abc123def456...",   // save this — not stored
  "key_meta": {
    "key_id": "key_...",
    "name": "Primary API key",
    "role": "admin"
  }
}
```

---

### Get My Key Info

```
GET /api/v1/me
```

**Response `200`:**
```json
{
  "key_id": "key_abc123",
  "tenant_id": "ten_...",
  "role": "admin",
  "created_at": "2026-04-08T12:00:00Z"
}
```

---

### Register Agent

```
POST /api/v1/agents
```
**Roles:** admin, ingest

```json
{
  "name": "data-pipeline-agent",
  "owner": "data-team",
  "description": "ETL pipeline that reads from S3",
  "allowed_domains": ["s3.amazonaws.com", "api.acme.com"]
}
```

**Response `200`:**
```json
{
  "agent_id": "agt_a1b2c3d4",
  "tenant_id": "ten_...",
  "name": "data-pipeline-agent",
  "owner": "data-team",
  "description": "ETL pipeline that reads from S3",
  "allowed_domains": ["s3.amazonaws.com", "api.acme.com"],
  "created_at": "2026-04-08T12:00:00Z"
}
```

---

### Submit Action (Guardian Interceptor)

```
POST /api/v1/monitor
```
**Roles:** admin, ingest

```json
{
  "agent_id": "agt_a1b2c3d4",
  "action": "http_call",
  "context": {"url": "https://api.example.com/data"},
  "source_url": "https://agent.acme.com/run",
  "metadata": {}
}
```

**Decision responses:**

`allowed` — action permitted:
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

`pending_approval` — queued for admin review:
```json
{
  "decision": "pending_approval",
  "reason": "High-risk action (score: 65) requires approval",
  "risk_score": 65,
  "requires_approval": true,
  "breakglass_used": false,
  "approval_id": "apr_abc123def456",
  "proof": null
}
```

`blocked` — action denied:
```json
{
  "decision": "blocked",
  "reason": "Critical action 'delete_all_files' is blocked",
  "risk_score": 100,
  "requires_approval": false,
  "breakglass_used": false,
  "approval_id": null,
  "proof": null
}
```

---

### List / Approve / Deny Pending Approvals

```
GET /api/v1/approvals
```
**Roles:** admin

List all pending approvals for your tenant.

**Response `200`:** array of `PendingApprovalRecord`

---

```
GET /api/v1/approvals/{approval_id}
```
**Roles:** admin

**Response `200`:**
```json
{
  "approval_id": "apr_abc123def456",
  "tenant_id": "ten_...",
  "agent_id": "agt_a1b2c3d4",
  "action": "http_call",
  "context": {"url": "https://api.example.com/data"},
  "actor": "key_abc123",
  "risk_score": 65,
  "created_at": "2026-04-08T12:00:00Z",
  "status": "pending",
  "decision": null,
  "decided_by": null,
  "decided_at": null
}
```

---

```
POST /api/v1/approvals/{approval_id}/decide
```
**Roles:** admin | **Content-Type:** `application/json`

Decision is provided in the request body, not as a query parameter.

**Request body:**
```json
{"decision": "approve"}
```
or `{"decision": "deny"}`

**Response `200`:** updated `PendingApprovalRecord`

**Response `400`** — already decided:
```json
{"detail": "Approval has already been decided"}
```

---

### Breakglass

```
POST /api/v1/breakglass
```
**Roles:** admin
**Auth:** Requires PIN via `X-Breakglass-Pin` header

```json
{
  "reason": "Production data deletion emergency — incident INC-1234"
}
```
Reason must be ≥10 characters.

Header: `X-Breakglass-Pin: ai-guardian-breakglass-2026`

**Response `200`:**
```json
{
  "breakglass_id": "bg_abc123def456",
  "approved": true,
  "expires_at": "2026-04-08T12:15:00Z",
  "actor": "key_abc123"
}
```

---

```
POST /api/v1/breakglass/{breakglass_id}/use?action={action}&confirm=BREAKGLASS
```
**Roles:** admin

One-time use. Requires confirmation token `BREAKGLASS` to prevent accidental triggers.

**Query parameters:**
- `action` — the action to override (e.g. `delete_all_files`)
- `confirm` — must be `BREAKGLASS` (exact, uppercase)

**Response `200`:**
```json
{"breakglass_used": true, "action": "delete_all_files"}
```

**Response `400`** — already used, revoked, or confirmation missing:
```json
{"detail": "Breakglass session has already been used"}
```

---

```
POST /api/v1/breakglass/{breakglass_id}/revoke
```
**Roles:** admin

Revokes a breakglass session immediately.

---

```
POST /api/v1/breakglass/pin/rotate
```
**Roles:** admin | **Content-Type:** `application/json`

Rotates the breakglass PIN. Requires the current PIN and the new PIN. After rotation, the old PIN is immediately invalid and only the new PIN is valid. All active breakglass sessions remain valid.

**Request body:**
```json
{
  "current_pin": "ai-guardian-breakglass-2026",
  "new_pin": "my-new-secure-pin-123"
}
```

**Response `200`:**
```json
{"status": "rotated", "pin_hash": "sha256:..."}
```

**Response `400`** — new PIN too short (min 6 chars):
```json
{"detail": "New PIN must be at least 6 characters."}
```

**Response `401`** — wrong current PIN:
```json
{"detail": "Current PIN is incorrect."}
```

---

### Audit Log

```
GET /api/v1/audit/logs?limit={100}&decision={allowed|blocked|pending_approval}
```
**Roles:** admin, viewer

Returns hash-chained audit entries for your tenant, newest first.
Use `?decision=blocked` to see only blocked actions, `?decision=allowed` for allowed, etc.

---
```
GET /api/v1/audit/blocked?limit={100}
```
**Roles:** admin, viewer

Shortcut for `?decision=blocked` — returns all blocked actions.

---
```
GET /api/v1/audit/verify
```
**Roles:** admin

Verifies hash chain integrity.

**Response `200`:**
```json
{
  "valid": true,
  "errors": []
}
```

If tampered:
```json
{
  "valid": false,
  "errors": ["Entry 3: broken chain link (expected abc123... got def456...)"]
}
```

---

### API Keys

```
POST /api/v1/api-keys?name={name}&role={admin|ingest|viewer}
```
**Roles:** admin

Create a new API key. Key value returned once.

```
POST /api/v1/api-keys/{key_id}/rotate
```
**Roles:** admin

Rotate a key — old key invalidated, new key returned.

```
DELETE /api/v1/api-keys/{key_id}
```
**Roles:** admin

Revoke a key immediately.

---

## Response Schemas

### GuardianDecisionResponse
```json
{
  "decision": "allowed | blocked | pending_approval",
  "reason": "string",
  "risk_score": 0-100,
  "requires_approval": boolean,
  "breakglass_used": boolean,
  "approval_id": "apr_..." | null,
  "proof": "sha256_hex" | null
}
```

### PendingApprovalRecord
```json
{
  "approval_id": "apr_...",
  "tenant_id": "ten_...",
  "agent_id": "agt_...",
  "action": "string",
  "context": {},
  "actor": "key_id",
  "risk_score": 0-100,
  "created_at": "ISO8601",
  "status": "pending | approved | denied | expired",
  "decision": "approved | denied | null",
  "decided_by": "key_id | null",
  "decided_at": "ISO8601 | null"
}
```

### BreakglassRecord
```json
{
  "breakglass_id": "bg_...",
  "approved": true,
  "created_at": "ISO8601",
  "expires_at": "ISO8601",
  "actor": "key_id",
  "reason": "string (≥10 chars)",
  "tenant_id": "ten_...",
  "actions_overridden": ["action@timestamp"],
  "status": "active | used | expired | revoked",
  "used": false
}
```

### AuditRecord
```json
{
  "id": 1,
  "timestamp": "ISO8601",
  "actor": "key_id",
  "action": "guardian_allowed:read_data",
  "decision": "allowed",
  "context": {},
  "risk_score": 0,
  "breakglass_id": "bg_..." | null,
  "metadata": {},
  "prev_hash": "sha256_hex",
  "hash": "sha256_hex"
}
```

---

## Error Responses

| Code | Meaning |
|------|---------|
| `401` | Invalid or missing API key |
| `403` | Insufficient permissions (role check failed) |
| `404` | Resource not found (approval, breakglass, agent, etc.) |
| `422` | Validation error (missing fields, invalid values) |
| `429` | Rate limit exceeded |
| `400` | Bad request (e.g., approval already decided, breakglass already used) |

---

## Rate Limits

Default: 120 requests/minute per tenant (configurable via `AI_GUARDIAN_RATE_LIMIT_PER_MINUTE`).
