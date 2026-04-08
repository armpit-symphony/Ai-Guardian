# Pilot Checklist

Use this checklist to verify your Ai-Guardian pilot deployment is working correctly before going live with real agents.

---

## Pre-Flight (Before Any Agent Activity)

- [ ] Ai-Guardian is deployed and responding on expected port
- [ ] `GET /health` returns `200 OK`
- [ ] Bootstrap key is known and secured
- [ ] First admin tenant is created
- [ ] Admin API key is saved securely (not in code or plain text files)
- [ ] At least one ingest key created for your agent
- [ ] Agent registered with `POST /api/v1/agents`
- [ ] `agent_id` saved for use in monitor calls
- [ ] TLS proxy configured if accessible externally (see `docs/TLS_DEPLOYMENT.md`)
- [ ] Backup schedule configured (see `docs/DEPLOYMENT.md`)
- [ ] Pilot team has read `docs/pilot/PILOT_ONBOARDING.md`

---

## Core Workflows — Operator Tasks

### Safe Action (Should Be Allowed Immediately)
- [ ] Submit `read_logs` action via `POST /api/v1/monitor`
- [ ] Response has `decision: "allowed"`
- [ ] Action appears in `GET /api/v1/audit/logs`

### Pending Approval Flow
- [ ] Submit `execute_code` action via `POST /api/v1/monitor`
- [ ] Response has `decision: "pending_approval"` and an `approval_id`
- [ ] `GET /api/v1/approvals` shows the pending item
- [ ] `POST .../decide?decision=approve` approves it successfully
- [ ] `GET /api/v1/approvals` no longer shows the item
- [ ] Audit log shows `pending_approval` → `approved` chain

### Denial Flow
- [ ] Submit `execute_code` action (new pending)
- [ ] `POST .../decide?decision=deny` denies it
- [ ] Audit log shows `pending_approval` → `denied` chain

### Blocked Action
- [ ] Submit `delete_all_files` via `POST /api/v1/monitor`
- [ ] Response has `decision: "blocked"`
- [ ] `risk_score` is present and ≥ 80
- [ ] Blocked action appears in `GET /api/v1/audit/blocked`

### SSRF Protection
- [ ] Submit action with `context.source_url: "http://localhost:6379"`
  - Expected: `decision: "blocked"`, `reason` contains "internal"
- [ ] Submit action with `context.source_url: "http://169.254.169.254/..."`
  - Expected: `decision: "blocked"`, SSRF reason
- [ ] Submit action with `context: {"url": "http://[::1]:22"}`
  - Expected: `decision: "blocked"` (context scan catches nested URLs)

### Breakglass (Test with Expiry = 1 minute)
- [ ] Create breakglass session with valid PIN → `breakglass_id` returned
- [ ] Create breakglass with wrong PIN → `401` returned
- [ ] Use breakglass with `&confirm=BREAKGLASS` → `200` returned
- [ ] Re-use same breakglass → `400` (one-time only)
- [ ] Revoke unused breakglass → `200`, session invalidated
- [ ] Audit log shows `breakglass_create`, `breakglass_override`, `breakglass_revoke` events

### PIN Rotation
- [ ] `POST /api/v1/breakglass/pin/rotate` with correct current PIN → `200`, new hash returned
- [ ] Old PIN no longer works
- [ ] New PIN works
- [ ] `breakglass_pin_rotated` event in audit log

---

## Visibility & Reporting

- [ ] `GET /api/v1/audit/logs` returns entries newest-first
- [ ] `GET /api/v1/audit/logs?decision=blocked` filters correctly
- [ ] `GET /api/v1/audit/blocked` returns only blocked actions
- [ ] `GET /api/v1/audit/verify` returns `valid: true`
- [ ] `GET /api/v1/status` (admin only) shows correct counts

---

## Operational Checks

- [ ] Restart Ai-Guardian process — data persists (pending approvals survive restart)
- [ ] Restart Ai-Guardian — breakglass sessions with remaining TTL are still valid
- [ ] After restart: `GET /api/v1/audit/verify` still returns `valid: true`
- [ ] Multiple concurrent pending approvals: all display and can be decided independently
- [ ] Ingest key can ONLY submit monitor requests (not approve, not create keys)
- [ ] Viewer key can ONLY read audit logs and health (not submit or decide)

---

## Security Checks

- [ ] Wrong API key → `401 Unauthorized`
- [ ] Viewer key trying to approve → `403 Forbidden`
- [ ] Expired breakglass session cannot be used
- [ ] SSRF: internal URLs blocked even in nested context structures
- [ ] Audit hash chain remains valid after multiple operations

---

## Sign-Off

- [ ] All items checked above pass
- [ ] Pilot team has been briefed on breakglass policy
- [ ] Emergency contact (who has breakglass PIN) is known
- [ ] Backup procedure confirmed working
- [ ] Pilot feedback template shared with team
- [ ] Ready to connect real agent workload
