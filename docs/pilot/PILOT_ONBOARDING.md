# Pilot Onboarding Guide

Welcome to the Ai-Guardian pilot! This guide walks you through getting your first tenant running and executing the core operator workflows.

---

## What Is Ai-Guardian?

Ai-Guardian is a governance layer for autonomous AI agents. It:
- **Blocks** critical/destructive actions by default
- **Requires approval** for high-risk actions via a pending queue
- **Logs everything** in a tamper-evident audit trail
- **Supports emergency overrides** via breakglass (with full audit)

---

## Before You Start

You need:
- Python 3.12+ installed, OR Docker
- A deployment endpoint (local or cloud)
- Your bootstrap key (from the operator who deployed Ai-Guardian)

---

## Step 1: Bootstrap Your Tenant

Ask your deployment administrator for:
- The `AI_GUARDIAN_BOOTSTRAP_KEYS` value
- The Ai-Guardian base URL (e.g. `http://localhost:8000`)

```bash
# Replace these with your actual values
BOOTSTRAP_KEY="your-bootstrap-key-here"
BASE_URL="http://your-guardian-instance:8000"

curl -X POST "${BASE_URL}/api/v1/bootstrap/tenants" \
  -H "X-Bootstrap-Key: ${BOOTSTRAP_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Your Company",
    "slug": "your-company",
    "contact_email": "you@company.com"
  }'
```

**Save the returned values:**
- `tenant_id` — your tenant identifier
- First `api_key` — your admin key (treat like a password)

---

## Step 2: Create API Keys

Create one key for each role you need:

```bash
ADMIN_KEY="your-admin-key-from-bootstrap"

# Admin key — full access
curl -X POST "${BASE_URL}/api/v1/api-keys?name=Admin+Key&role=admin" \
  -H "X-API-Key: ${ADMIN_KEY}"

# Ingest key — for your AI agent to submit actions
curl -X POST "${BASE_URL}/api/v1/api-keys?name=Agent+Ingest&role=ingest" \
  -H "X-API-Key: ${ADMIN_KEY}"

# Viewer key — for read-only dashboards
curl -X POST "${BASE_URL}/api/v1/api-keys?name=Auditor+View&role=viewer" \
  -H "X-API-Key: ${ADMIN_KEY}"
```

**Save each returned `api_key` — you won't see it again.**

---

## Step 3: Register Your AI Agent

```bash
curl -X POST "${BASE_URL}/api/v1/agents" \
  -H "X-API-Key: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent", "description": "Production AI agent"}'
```

Save the returned `agent_id`.

---

## Step 4: Submit Your First Action

Submit a **safe read action** (should be allowed immediately):

```bash
INGEST_KEY="your-ingest-key"

curl -X POST "${BASE_URL}/api/v1/monitor" \
  -H "X-API-Key: ${INGEST_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_your-agent-id",
    "action": "read_logs",
    "context": {}
  }'
```

Expected response: `{"decision": "allowed", ...}`

---

## Step 5: Try a Pending Action

Submit an action that requires approval:

```bash
curl -X POST "${BASE_URL}/api/v1/monitor" \
  -H "X-API-Key: ${INGEST_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_your-agent-id",
    "action": "execute_code",
    "context": {"reason": "Running data transformation for report generation"}
  }'
```

Expected response: `{"decision": "pending_approval", "approval_id": "apr_...", ...}`

**Check pending approvals:**
```bash
curl "${BASE_URL}/api/v1/approvals" \
  -H "X-API-Key: ${ADMIN_KEY}"
```

**Approve it:**
```bash
APPROVAL_ID="apr_the-id-from-above"

curl -X POST "${BASE_URL}/api/v1/approvals/${APPROVAL_ID}/decide?decision=approve" \
  -H "X-API-Key: ${ADMIN_KEY}"
```

---

## Step 6: Try a Blocked Action

Submit an action that is always blocked:

```bash
curl -X POST "${BASE_URL}/api/v1/monitor" \
  -H "X-API-Key: ${INGEST_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_your-agent-id",
    "action": "delete_all_files",
    "context": {}
  }'
```

Expected response: `{"decision": "blocked", "reason": "Action delete_all_files is blocked by policy", ...}`

---

## Step 7: View the Audit Log

```bash
# All events
curl "${BASE_URL}/api/v1/audit/logs?limit=20" \
  -H "X-API-Key: ${ADMIN_KEY}"

# Only blocked actions
curl "${BASE_URL}/api/v1/audit/blocked?limit=20" \
  -H "X-API-Key: ${ADMIN_KEY}"

# Verify audit integrity
curl "${BASE_URL}/api/v1/audit/verify" \
  -H "X-API-Key: ${ADMIN_KEY}"
```

---

## Step 8: Test Breakglass (Emergency Only)

**⚠️ Only for genuine emergencies. Every use is permanently logged.**

First, get the breakglass PIN from your security team.

```bash
BG_PIN="your-breakglass-pin"

# Create a breakglass session (reason must be ≥10 chars)
curl -X POST "${BASE_URL}/api/v1/breakglass" \
  -H "X-API-Key: ${ADMIN_KEY}" \
  -H "X-Breakglass-Pin: ${BG_PIN}" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Production security incident - isolating NOW"}'
```

Save the returned `breakglass_id`.

**Use it to override a blocked action:**
```bash
BG_ID="bg_the-id-from-above"

curl -X POST "${BASE_URL}/api/v1/breakglass/${BG_ID}/use?action=delete_all_files&confirm=BREAKGLASS" \
  -H "X-API-Key: ${ADMIN_KEY}"
```

---

## What to Do If Something Goes Wrong

| Problem | What to check |
|---|---|
| 401 Unauthorized | Check your API key is correct and active |
| 403 Forbidden | Your key role doesn't have permission for this action |
| 404 Not Found | Check the endpoint path — use `/api-keys` (hyphen), not `/api_keys` (underscore) |
| Pending approval never resolves | Check `GET /api/v1/approvals` with your admin key |
| Guardian not responding | Check the Guardian service is running and port is accessible |

---

## Getting Help During the Pilot

If you encounter issues not covered here:

1. Check the full API docs: `docs/API.md`
2. Check the runbooks: `docs/BREAKGLASS_RUNBOOK.md`
3. Collect: endpoint, request, response, error message
4. Report via the pilot feedback template
