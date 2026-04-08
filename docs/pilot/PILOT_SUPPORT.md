# Pilot Support Checklist

Use this when a pilot user reports an issue. Work through each section in order.

---

## Section 1: Triage (30 seconds)

**Identify the problem category:**

| Category | Symptoms | Go to |
|---|---|---|
| **Auth failure** | 401 on every request | Section 2 |
| **Permission denied** | 403 on specific actions | Section 3 |
| **Unexpected allow** | Critical action returned `allowed` | Section 4 |
| **Unexpected block** | Safe action returned `blocked` | Section 5 |
| **Pending queue stuck** | Approval never resolves | Section 6 |
| **Breakglass not working** | Breakglass create/use fails | Section 7 |
| **Audit missing events** | Actions not appearing in log | Section 8 |
| **Service down** | /health returns non-200 | Section 9 |

---

## Section 2: Auth Failures (401)

**Common causes:**

1. **Wrong API key format**
   - Use `/api-keys` (hyphen), NOT `/api_keys` (underscore)
   - Check for trailing spaces or newlines in the key value

2. **Key was revoked**
   ```bash
   # List active keys
   curl http://localhost:8000/api/v1/api-keys \
     -H "X-API-Key: $ADMIN_KEY"
   ```

3. **Key role doesn't match the action**
   - Ingest keys can only call `POST /api/v1/monitor`
   - Viewer keys can only read audit/health
   - Admin keys can do everything

4. **Tenant mismatch**
   - Keys are scoped to a tenant
   - If you have multiple tenants, make sure you're using the right key

**Resolution:** Create a new key via `POST /api/v1/api-keys` with the correct role.

---

## Section 3: Permission Denied (403)

**Check the key's role:**
```bash
curl http://localhost:8000/api/v1/api-keys \
  -H "X-API-Key: $ADMIN_KEY"
```

**Common issues:**
- Ingest key trying to access admin-only endpoints
- Viewer key trying to approve or create breakglass
- Ingest key used for `POST /api/v1/api-keys` (admin only)

**Resolution:** Use the correct role key for the operation, or create a new admin key.

---

## Section 4: Unexpected Allow (Critical Action Allowed)

⚠️ **Security concern — investigate immediately.**

1. **What action was allowed?**
   - Was it genuinely safe (e.g., `read_logs`)?
   - Or was it a destructive action?

2. **Check the audit log:**
   ```bash
   curl "http://localhost:8000/api/v1/audit/logs?limit=50" \
     -H "X-API-Key: $ADMIN_KEY"
   ```

3. **Was a breakglass used legitimately?**
   - Look for `breakglass_override:{action}` in the audit log

4. **Was it a known-safe action?**
   - `read_logs`, `read_files` (non-destructive reads) are typically allowed
   - Check policy configuration

**If a critical action was wrongly allowed:** Contact the deployment team immediately with audit log evidence.

---

## Section 5: Unexpected Block (Safe Action Blocked)

1. **What action was blocked?**
   - Check `reason` and `risk_score` in the response

2. **Common causes:**
   - Action name similar to a blocked pattern (e.g., `delete_all` matches `delete_`)
   - SSRF: URL in context contains internal address
   - High risk score from context contents

3. **Check the audit log:**
   ```bash
   curl "http://localhost:8000/api/v1/audit/blocked?limit=20" \
     -H "X-API-Key: $ADMIN_KEY"
   ```

4. **Test with explicit context:**
   ```bash
   curl -X POST http://localhost:8000/api/v1/monitor \
     -H "X-API-Key: $INGEST_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "agent_id": "agt_test",
       "action": "YOUR_ACTION",
       "context": {}
     }'
   ```

5. **SSRF false positive?**
   - If context contains a URL that looks internal but isn't (e.g., a server named `localhost` in your internal DNS), this may be a false positive
   - Report it via feedback template

---

## Section 6: Pending Queue Stuck

1. **Check pending approvals:**
   ```bash
   curl http://localhost:8000/api/v1/approvals \
     -H "X-API-Key: $ADMIN_KEY"
   ```

2. **Is the approval still in `pending` state?**
   - It should have a `status: pending` field

3. **Has it expired?**
   - Check `expires_at` timestamp — approvals may have a TTL

4. **Was it already decided?**
   - Re-deciding an already-decided approval returns `400 Bad Request`
   - Check audit log for the original decision

5. **Concurrent decision race?**
   - Only one decision (approve/deny) can be recorded
   - Second caller gets an error

**Resolution:** If stuck with no clear cause, deny it and submit a fresh approval request.

---

## Section 7: Breakglass Failures

### "Breakglass not found" (404)
- Check the `breakglass_id` is correct
- Breakglass sessions expire — check `expires_at`

### "Session already used" (400)
- Breakglass is **one-time use only**
- Create a new session if you need another override

### "Session expired" (400)
- Breakglass sessions have a 15-minute default TTL (configurable at creation)
- Create a new session if needed

### Wrong PIN (401)
- PIN must match exactly — check for case sensitivity
- PIN is the value set at deployment, not the default from docs

### "Missing or invalid confirmation" (400)
- Add `&confirm=BREAKGLASS` to the `/use` URL
- Full example: `/api/v1/breakglass/{id}/use?action=delete_files&confirm=BREAKGLASS`

---

## Section 8: Audit Missing Events

1. **Check audit integrity first:**
   ```bash
   curl http://localhost:8000/api/v1/audit/verify \
     -H "X-API-Key: $ADMIN_KEY"
   ```
   - If `valid: false` — data corruption or tampering detected, escalate immediately

2. **Check the correct tenant:**
   - Audit logs are scoped per tenant
   - Using an admin key from the wrong tenant = empty results

3. **Check time range:**
   ```bash
   # Default limit is small — increase it
   curl "http://localhost:8000/api/v1/audit/logs?limit=500" \
     -H "X-API-Key: $ADMIN_KEY"
   ```

4. **Is the action in a different decision category?**
   - `GET /api/v1/audit/logs?decision=allowed`
   - `GET /api/v1/audit/logs?decision=blocked`
   - `GET /api/v1/audit/logs?decision=pending_approval`

---

## Section 9: Service Unavailable

1. **Check if the service is running:**
   ```bash
   curl http://localhost:8000/health
   ```

2. **Check the process:**
   ```bash
   ps aux | grep ai_guardian
   ```

3. **Check disk space:**
   ```bash
   df -h
   ```
   - Low disk space can cause write failures

4. **Check database file:**
   ```bash
   ls -la /app/data/ai_guardian.db  # or your DB path
   ```

5. **Restart the service** (if authorized):
   ```bash
   # Find the process
   ps aux | grep uvicorn
   
   # Kill and restart
   kill <PID>
   python -m ai_guardian.main &
   ```

**After restart:** Re-verify audit integrity:
```bash
curl http://localhost:8000/api/v1/audit/verify \
  -H "X-API-Key: $ADMIN_KEY"
```

---

## Escalation Criteria

Escalate to the Ai-Guardian deployment team if:
- [ ] Audit verify returns `valid: false`
- [ ] A critical action was allowed without a corresponding breakglass audit entry
- [ ] Breakglass PIN is compromised or lost
- [ ] Service crashes repeatedly
- [ ] Database file is corrupted or missing
- [ ] Any security-relevant anomaly

**When escalating, include:**
1. Tenant ID
2. Timestamp of incident
3. API endpoint and request that caused the issue
4. Response received
5. `GET /api/v1/audit/verify` output
