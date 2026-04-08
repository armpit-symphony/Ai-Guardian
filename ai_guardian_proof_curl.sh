#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Ai-Guardian — Adversarial Proof Package (CURL BLOCK)
# Phase 4 Enforcement — Human-verifiable smoke test
# ═══════════════════════════════════════════════════════════════════
#
# USAGE:
#   1. Start the server:
#      cd /tmp/Ai-Guardian
#      PYTHONPATH=. ENVIRONMENT=local .venv/bin/uvicorn ai_guardian.main:app --host 127.0.0.1 --port 7419 &
#      sleep 2
#
#   2. Run this script:
#      bash ai_guardian_proof_curl.sh
#
#   3. Verify each section matches the expected column.
#
# EXPECTED AUDIT TAXONOMY (from Python proof run):
#   Decisions:    allowed, blocked, pending_approval, approve, deny, breakglass_used
#   Guardian actions:  guardian_pending:{action}, guardian_allowed:{action},
#                      guardian_approval_approved:{action}, guardian_approval_denied:{action},
#                      guardian_blocked_critical:{action}, guardian_blocked:ssrf:{action}
#   Breakglass actions: breakglass_create, breakglass_override:{action}, breakglass_revoke
#
# ──────────────────────────────────────────────────────────────────

BASE="http://127.0.0.1:7419"
BOOT_KEY="dev-guardian-key"

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  Ai-Guardian — Adversarial Proof Package (curl)                     ║"
echo "║  Phase 4 Enforcement                                               ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# ── Setup: Bootstrap tenant ──────────────────────────────────────────
echo "── [SETUP] Bootstrap tenant ─────────────────────────────────────────"
BOOT_RESP=$(curl -s -X POST "$BASE/api/v1/bootstrap/tenants" \
  -H "x-bootstrap-key: $BOOT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Proof Tenant","slug":"ten-proof-curl","contact_email":"phil@proof.test"}')
ADMIN_KEY=$(echo "$BOOT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
echo "  Admin key: ${ADMIN_KEY:0:25}..."
echo ""

# ── [PROOF 1] AUTH PATH ─────────────────────────────────────────────
echo "── [PROOF 1] AUTH PATH ──────────────────────────────────────────────"
echo ""

# 1a: Create ingest key
echo "1a. Create ingest key (role=ingest, name=IngestWorker)"
ING_RESP=$(curl -s -X POST "$BASE/api/v1/api-keys" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"IngestWorker","role":"ingest"}')
INGEST_KEY=$(echo "$ING_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])" 2>/dev/null)
echo "  INGEST_KEY: ${INGEST_KEY:0:25}..."
echo ""

# 1b: Create viewer key
echo "1b. Create viewer key (role=viewer, name=ViewerWorker)"
VIEW_RESP=$(curl -s -X POST "$BASE/api/v1/api-keys" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"ViewerWorker","role":"viewer"}')
VIEWER_KEY=$(echo "$VIEW_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])" 2>/dev/null)
echo "  VIEWER_KEY: ${VIEWER_KEY:0:25}..."
echo ""

# 1c: Ingest /me → api_key.role == "ingest"
echo "1c. GET /me with ingest key → api_key.role"
ME_ING=$(curl -s -X GET "$BASE/api/v1/me" -H "x-api-key: $INGEST_KEY")
ROLE_ING=$(echo "$ME_ING" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key']['role'])" 2>/dev/null)
echo "  EXPECTED: role = 'ingest'"
echo "  ACTUAL:   role = '$ROLE_ING'"
echo ""

# 1d: Viewer /me → api_key.role == "viewer"
echo "1d. GET /me with viewer key → api_key.role"
ME_VIEW=$(curl -s -X GET "$BASE/api/v1/me" -H "x-api-key: $VIEWER_KEY")
ROLE_VIEW=$(echo "$ME_VIEW" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key']['role'])" 2>/dev/null)
echo "  EXPECTED: role = 'viewer'"
echo "  ACTUAL:   role = '$ROLE_VIEW'"
echo ""

# 1e: Bad key → 401
echo "1e. Invalid key → 401"
BAD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE/api/v1/me" -H "x-api-key: bad_key_xyz")
echo "  EXPECTED: 401"
echo "  ACTUAL:   $BAD_STATUS"
echo ""

# 1f: No key → 422
echo "1f. Missing key → 422"
NO_KEY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE/api/v1/me")
echo "  EXPECTED: 422"
echo "  ACTUAL:   $NO_KEY_STATUS"
echo ""


# ── [PROOF 2] ENFORCEMENT PATH ──────────────────────────────────────
echo "── [PROOF 2] ENFORCEMENT PATH ──────────────────────────────────────"
echo ""

# 2a: ingest + http_call → pending_approval
echo "2a. POST /monitor with ingest+http_call → pending_approval"
MON_RESP=$(curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $INGEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agt_proof","action":"http_call","context":{}}')
DECISION=$(echo "$MON_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null)
APPROVAL_ID=$(echo "$MON_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['approval_id'])" 2>/dev/null)
RISK=$(echo "$MON_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_score'])" 2>/dev/null)
echo "  EXPECTED: decision=pending_approval, approval_id!=null, risk=65"
echo "  ACTUAL:   decision=$DECISION, approval_id=$APPROVAL_ID, risk=$RISK"
echo ""

# 2b: admin + external_api_call → pending_approval
echo "2b. POST /monitor with admin+external_api_call → pending_approval"
EXT_RESP=$(curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agt_proof","action":"external_api_call","context":{}}')
EXT_DEC=$(echo "$EXT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null)
echo "  EXPECTED: decision=pending_approval"
echo "  ACTUAL:   decision=$EXT_DEC"
echo ""

# 2c: viewer + read_logs → RBAC block (200+blocked)
echo "2c. POST /monitor with viewer+read_logs → RBAC block"
VIEW_MON=$(curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $VIEWER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agt_proof","action":"read_logs","context":{}}')
VIEW_DEC=$(echo "$VIEW_MON" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null)
echo "  EXPECTED: status=200, decision=blocked"
echo "  ACTUAL:   status=200, decision=$VIEW_DEC"
echo ""


# ── [PROOF 3] APPROVAL PATH ─────────────────────────────────────────
echo "── [PROOF 3] APPROVAL PATH ────────────────────────────────────────"
echo ""

# 3a: Admin approves
echo "3a. POST /approvals/{id}/decide with decision=approve → approved"
APPR_RESP=$(curl -s -X POST "$BASE/api/v1/approvals/$APPROVAL_ID/decide" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approve"}')
STATUS=$(echo "$APPR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
echo "  EXPECTED: status=approved"
echo "  ACTUAL:   status=$STATUS"
echo ""

# 3b: Second approval → rejected
echo "3b. Second approve attempt → 400"
SECOND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/approvals/$APPROVAL_ID/decide" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approve"}')
echo "  EXPECTED: 4xx"
echo "  ACTUAL:   $SECOND_STATUS"
echo ""

# 3c: List approvals
echo "3c. GET /approvals → 200"
LIST_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE/api/v1/approvals" \
  -H "x-api-key: $ADMIN_KEY")
echo "  EXPECTED: 200"
echo "  ACTUAL:   $LIST_STATUS"
echo ""


# ── [PROOF 4] NEGATIVE PATH ───────────────────────────────────────────
echo "── [PROOF 4] NEGATIVE PATH ─────────────────────────────────────────"
echo ""

for ACTION in "delete_all_files" "exec_code"; do
  echo "4x. POST /monitor with admin+$ACTION → blocked"
  NEG_RESP=$(curl -s -X POST "$BASE/api/v1/monitor" \
    -H "x-api-key: $ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"agt_proof\",\"action\":\"$ACTION\",\"context\":{}}")
  NEG_DEC=$(echo "$NEG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null)
  echo "  EXPECTED: decision=blocked"
  echo "  ACTUAL:   decision=$NEG_DEC"
  echo ""
done


# ── [PROOF 5] AUDIT COMPLETENESS ──────────────────────────────────────
echo "── [PROOF 5] AUDIT COMPLETENESS ────────────────────────────────────"
echo ""

# 5a: Read logs → allowed
echo "5a. read_logs → allowed"
curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agt","action":"read_logs","context":{}}' > /dev/null

# 5b: exec_code → blocked
echo "5b. exec_code → blocked"
curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agt","action":"exec_code","context":{}}' > /dev/null

# 5c: send_webhook → denied
echo "5c. send_webhook → denied"
curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agt","action":"send_webhook","context":{}}' > /dev/null

echo "5d. Fetch audit log"
AUDIT_RESP=$(curl -s -X GET "$BASE/api/v1/audit/logs" \
  -H "x-api-key: $ADMIN_KEY")
echo "  Decisions in log:"
echo "$AUDIT_RESP" | python3 -c "import sys,json; logs=json.load(sys.stdin); [print(f'    {e[\"decision\"]}') for e in logs]"
echo "  Actions in log:"
echo "$AUDIT_RESP" | python3 -c "import sys,json; logs=json.load(sys.stdin); [print(f'    {e[\"action\"]}') for e in logs]"
echo ""

echo "5e. Audit verify"
VERIFY_RESP=$(curl -s -X GET "$BASE/api/v1/audit/verify" \
  -H "x-api-key: $ADMIN_KEY")
VERIFY_VALID=$(echo "$VERIFY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])" 2>/dev/null)
echo "  EXPECTED: valid=True"
echo "  ACTUAL:   valid=$VERIFY_VALID"
echo ""


# ── [PROOF 6] SSRF PROTECTION ────────────────────────────────────────
echo "── [PROOF 6] SSRF PROTECTION ───────────────────────────────────────"
echo ""

SSRF_CASES=(
  "http://localhost:6379:localhost"
  "http://127.0.0.1:22:127.0.0.1"
  "http://169.254.169.254/:169.254.169.254"
  "http://[::1]:22:IPv6 ::1"
  "http://metadata.google.internal/:metadata.google.internal"
)

for CASE in "${SSRF_CASES[@]}"; do
  URL="${CASE%%:*}"
  LABEL="${CASE##*:}"
  echo "6. SSRF $LABEL → blocked, risk=100"
  SSRF_RESP=$(curl -s -X POST "$BASE/api/v1/monitor" \
    -H "x-api-key: $ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"agt\",\"action\":\"fetch_url\",\"context\":{},\"source_url\":\"$URL\"}")
  SSRF_DEC=$(echo "$SSRF_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])" 2>/dev/null)
  SSRF_RISK=$(echo "$SSRF_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_score'])" 2>/dev/null)
  echo "  EXPECTED: decision=blocked, risk=100"
  echo "  ACTUAL:   decision=$SSRF_DEC, risk=$SSRF_RISK"
  echo ""
done


# ── [PROOF 7] REPLAY SAFETY ───────────────────────────────────────────
echo "── [PROOF 7] REPLAY SAFETY ─────────────────────────────────────────"
echo ""

# 7a: Double-approve idempotent
echo "7a. Double-approve → 400"
EXT_MON=$(curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"a","action":"external_api_call","context":{}}')
AID_EXT=$(echo "$EXT_MON" | python3 -c "import sys,json; print(json.load(sys.stdin)['approval_id'])" 2>/dev/null)
curl -s -X POST "$BASE/api/v1/approvals/$AID_EXT/decide" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approve"}' > /dev/null
DA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/approvals/$AID_EXT/decide" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approve"}')
echo "  EXPECTED: 4xx"
echo "  ACTUAL:   $DA_STATUS"
echo ""

# 7b: Revoked breakglass → fails
echo "7b. Revoked breakglass use → 400"
BG_RESP=$(curl -s -X POST "$BASE/api/v1/breakglass" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason":"revoke test session required here","duration_minutes":5,"pin":"ai-guardian-breakglass-2026"}')
BG_ID=$(echo "$BG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['breakglass_id'])" 2>/dev/null)
curl -s -X POST "$BASE/api/v1/breakglass/$BG_ID/revoke" \
  -H "x-api-key: $ADMIN_KEY" > /dev/null
BG_USE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/breakglass/$BG_ID/use?action=delete_all_files" \
  -H "x-api-key: $ADMIN_KEY")
echo "  EXPECTED: 4xx"
echo "  ACTUAL:   $BG_USE_STATUS"
echo ""

# 7c: One-time breakglass reuse
echo "7c. One-time breakglass reuse → 400"
BG3_RESP=$(curl -s -X POST "$BASE/api/v1/breakglass" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason":"one time use breakglass session for test","duration_minutes":5,"pin":"ai-guardian-breakglass-2026"}')
BG3_ID=$(echo "$BG3_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['breakglass_id'])" 2>/dev/null)
curl -s -X POST "$BASE/api/v1/breakglass/$BG3_ID/use?action=delete_all_files" \
  -H "x-api-key: $ADMIN_KEY" > /dev/null
BG3_REUSE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/breakglass/$BG3_ID/use?action=delete_all_files" \
  -H "x-api-key: $ADMIN_KEY")
echo "  EXPECTED: 4xx"
echo "  ACTUAL:   $BG3_REUSE_STATUS"
echo ""

# 7d: Double-deny idempotent
echo "7d. Double-deny → 400"
SWEB_RESP=$(curl -s -X POST "$BASE/api/v1/monitor" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"a","action":"send_webhook","context":{}}')
AID_SW=$(echo "$SWEB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['approval_id'])" 2>/dev/null)
curl -s -X POST "$BASE/api/v1/approvals/$AID_SW/decide" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"decision":"deny"}' > /dev/null
DD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/approvals/$AID_SW/decide" \
  -H "x-api-key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"decision":"deny"}')
echo "  EXPECTED: 4xx"
echo "  ACTUAL:   $DD_STATUS"
echo ""


echo "══════════════════════════════════════════════════════════════════════"
echo "CURL BLOCK COMPLETE"
echo "Verify each block above matches the expected column."
echo "══════════════════════════════════════════════════════════════════════"
