# Breakglass Runbook

## What Is Breakglass?

Breakglass provides **emergency override capability** when a blocked action must be executed immediately and the normal approval queue is too slow.

It is NOT a convenience feature. Every use is logged and auditable.

---

## When to Use Breakglass

Use breakglass only when ALL of these are true:

1. An action is blocked by AI Guardian
2. The action must be executed immediately (genuine emergency)
3. The normal approval process cannot complete in time
4. A business justification exists and can be documented

**Examples:**
- Production security incident requiring immediate action
- Data breach response
- Critical infrastructure failure requiring emergency access

**Do NOT use breakglass for:**
- Convenience (avoiding the approval queue)
- Testing
- Actions that could wait for normal approval

---

## Step-by-Step Emergency Procedure

### Phase 1: Assess

Confirm the action is genuinely blocked and understand why:

```bash
curl -X POST http://localhost:8000/api/v1/monitor \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_abc123",
    "action": "delete_all_files",
    "context": {"urgency": "critical"}
  }'
```

Expected response: `"decision": "blocked"` or `"decision": "pending_approval"`.

---

### Phase 2: Create Breakglass Session

Obtain the breakglass PIN from your secure credentials store.

```bash
curl -X POST http://localhost:8000/api/v1/breakglass \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Production security incident — attacker has access, isolating system NOW",
    "pin": "ai-guardian-breakglass-2026"
  }'
```

**Important:** The reason field must be ≥10 characters. Write the breakglass ID returned in the response.

Response:
```json
{
  "breakglass_id": "bg_xyz789...",
  "approved": true,
  "expires_at": "2026-04-08T12:15:00Z",
  "actor": "key_abc123"
}
```

---

### Phase 3: Execute the Override

Use the breakglass to override the blocked action (requires confirmation):

```bash
curl -X POST "http://localhost:8000/api/v1/breakglass/bg_xyz789.../use?action=delete_all_files&confirm=BREAKGLASS" \
  -H "X-API-Key: $ADMIN_KEY"
```

Response:
```json
{"breakglass_used": true, "action": "delete_all_files"}
```

⚠️ **This is a one-time use. The session is now permanently disabled.**

---

### Phase 4: Document

Immediately after use, document:
- Incident ticket number
- Actions taken
- Breakglass ID (`bg_xyz789...`)
- Timestamp
- Business justification (already in the reason field)

---

### Phase 5: Revoke When Done

If you created a breakglass but didn't need to use it, revoke it immediately:

```bash
curl -X POST "http://localhost:8000/api/v1/breakglass/bg_xyz789.../revoke" \
  -H "X-API-Key: $ADMIN_KEY"
```

---

## Verify Breakglass State Post-Restart

Breakglass sessions survive service restarts. After any restart, verify:

```bash
# View all breakglass sessions
curl http://localhost:8000/api/v1/breakglass \
  -H "X-API-Key: $ADMIN_KEY"

# Verify used sessions are still blocked
# (a used breakglass cannot be reused — even after restart)
```

---

## Audit Trail

Every breakglass event is written to the immutable audit log:

| Event | Audit Action |
|-------|-------------|
| Session created | `breakglass_create` |
| Override used | `breakglass_override:{action}` |
| Session revoked | `breakglass_revoke` |
| Use attempt after expiry | logged as failed attempt |

View audit trail:
```bash
curl "http://localhost:8000/api/v1/audit/logs?limit=100" \
  -H "X-API-Key: $ADMIN_KEY"
```

---

## Production PIN Management

The default PIN (`ai-guardian-breakglass-2026`) must be changed in production.

**To change:**
Use the PIN rotation endpoint (admin only, requires current PIN):

```bash
curl -X POST "http://localhost:8000/api/v1/breakglass/pin/rotate" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"current_pin": "ai-guardian-breakglass-2026", "new_pin": "your-new-pin-here"}'
```

The old PIN is immediately invalid after rotation; only the new PIN works. Rotation is logged as `breakglass_pin_rotated` in the audit log.

**Best practices:**
- Store breakglass PIN in a secrets manager (not in code)
- Limit who knows the PIN (only senior ops/on-call)
- Log every PIN access
- Rotate PIN quarterly or after any suspected compromise

---

## Breakglass vs Approval Queue

| Aspect | Approval Queue | Breakglass |
|--------|----------------|------------|
| Speed | Minutes | Seconds |
| Use case | Normal high-risk actions | True emergencies |
| Reusable | Yes (multiple approvals) | No (one-time per session) |
| Auditor | Admin team | Emergency responders only |
| Auto-expiry | No | 15 minutes |
| Requires PIN | No | Yes |
| Logged | Yes | Yes |

---

## Common Errors

**"Breakglass session not found"**
→ Wrong breakglass_id, or session has expired.

**"Breakglass session has already been used"**
→ Session was already used once (one-time enforcement). Create a new session if genuinely needed.

**"Breakglass session has expired"**
→ Session expired after 15 minutes. Create a new session if genuinely needed.

**"Breakglass session is revoked"**
→ Session was revoked. Create a new session if genuinely needed.

**"Invalid PIN or reason too short"**
→ PIN is wrong OR reason is fewer than 10 characters.
