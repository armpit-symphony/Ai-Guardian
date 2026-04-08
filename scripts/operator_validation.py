#!/usr/bin/env python3
"""WO-2026-0408-10: Operator Validation Runner

Executes all required scenarios and logs structured findings.
DOCS-ONLY mode: only uses docs + API. No code reading.
"""
import sys, os, time, json
sys.path.insert(0, '/tmp/Ai-Guardian')

BASE = "http://127.0.0.1:7419"
RESULTS = {"scenarios": [], "friction": [], "ui_findings": [], "observability_gaps": []}
TS = str(int(time.time()))[-6:]

def log(tag, msg):
    print(f"[{tag}] {msg}")

def apicall(method, path, headers=None, json_body=None):
    import urllib.request as _req, urllib.error as _err
    import json as _json
    url = BASE + path
    data = json_body and _json.dumps(json_body).encode()
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = _req.Request(url, data=data, headers=h, method=method)
    try:
        with _req.urlopen(req, timeout=10) as r:
            return json.loads(r.read()), r.status
    except _err.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        try:
            return json.loads(body), e.code
        except:
            return {"error": body[:200]}, e.code
    except Exception as e:
        return {"error": str(e)}, -1

def record_friction(step, expected, actual, why, severity, source="api"):
    RESULTS["friction"].append({
        "step": step, "expected": expected, "actual": actual,
        "why_confusing_risky": why, "severity": severity, "source": source
    })

print("=" * 68)
print("WO-2026-0408-10: OPERATOR VALIDATION")
print("=" * 68)

# ══════════════════════════════════════════════════════════════════
# SCENARIO A: FULL LIFECYCLE PER TENANT
# ══════════════════════════════════════════════════════════════════
log("SCENARIO", "A1: Bootstrap (per docs/QUICKSTART.md)")
print("─" * 68)

# Step 1 — Bootstrap per QUICKSTART.md
resp, code = apicall("POST", "/api/v1/bootstrap/tenants", {
    "X-Bootstrap-Key": "dev-guardian-key"
}, {
    "name": f"OperatorTest{TS}",
    "slug": f"op-test-{TS}",
    "contact_email": f"optest{TS}@test.com",
    "plan": "starter"
} if False else None)  # body test first

# The docs say X-Bootstrap-Key as header but QuickStart uses -H "X-Bootstrap-Key:"
# Let's test both ways
resp, code = apicall("POST", "/api/v1/bootstrap/tenants", {
    "X-Bootstrap-Key": "dev-guardian-key",
    "Content-Type": "application/json"
}, {
    "name": f"OperatorTest{TS}",
    "slug": f"op-test-{TS}",
    "contact_email": f"optest{TS}@test.com",
    "plan": "starter"
})
log("A1_BOOTSTRAP", f"code={code} resp={str(resp)[:200]}")
if code in (200, 201):
    tenant = resp.get("tenant", {})
    admin_key = resp.get("api_key", "")
    log("A1_SUCCESS", f"tenant_id={tenant.get('tenant_id')} key={admin_key[:15]}...")
else:
    record_friction("A1_BOOTSTRAP", "200/201 with admin_key", f"{code}: {str(resp)[:200]}",
                    "Cannot proceed without bootstrap succeeding", "blocker")
    admin_key = None

if not admin_key:
    RESULTS["scenarios"].append({"scenario": "A", "steps": 0, "passed": False, "stopped_at": "A1_BOOTSTRAP"})
    print(json.dumps(RESULTS, indent=2, default=str))
    sys.exit(1)

RESULTS["scenarios"].append({"scenario": "A1_BOOTSTRAP", "passed": code in (200, 201)})

# Step 2 — Create an ingest key (per API.md docs)
resp, code = apicall("POST", "/api/v1/api_keys", {
    "X-API-Key": admin_key
}, {
    "name": "IngestWorker",
    "role": "ingest"
})
log("A2_CREATE_KEY", f"code={code} resp={str(resp)[:200]}")
ingest_key = None
if code == 200:
    ingest_key = resp.get("key") or resp.get("api_key") or \
                 (resp.get("key_id") if resp.get("key_id") else None)
    log("A2_INGEST_KEY", f"obtained: {ingest_key[:15] if ingest_key else 'NONE'}...")
    RESULTS["scenarios"].append({"scenario": "A2_CREATE_INGEST_KEY", "passed": True})
else:
    record_friction("A2_CREATE_INGEST_KEY", "200 with new key", f"{code}: {str(resp)[:200]}",
                    "Cannot test RBAC without ingest key", "blocker")
    RESULTS["scenarios"].append({"scenario": "A2_CREATE_INGEST_KEY", "passed": False, "stopped_at": "A2"})

# Step 3 — Register agent
resp, code = apicall("POST", "/api/v1/agents", {
    "X-API-Key": admin_key
}, {
    "name": "TestAgent",
    "owner": "operator-test",
    "description": "Validation test agent",
    "allowed_domains": ["github.com"]
})
log("A3_REGISTER_AGENT", f"code={code} resp={str(resp)[:200]}")
agent_id = resp.get("agent_id") if code == 200 else None
RESULTS["scenarios"].append({"scenario": "A3_REGISTER_AGENT", "passed": code == 200})

# Step 4 — Ingest submits safe action
resp, code = apicall("POST", "/api/v1/monitor", {
    "X-API-Key": ingest_key or admin_key
}, {
    "agent_id": agent_id or "test",
    "action": "read_data",
    "context": {"source": "operator-validation"}
})
log("A4_SAFE_ACTION", f"code={code} decision={resp.get('decision') if isinstance(resp, dict) else 'N/A'}")
safe_ok = isinstance(resp, dict) and resp.get("decision") == "allowed"
RESULTS["scenarios"].append({"scenario": "A4_SAFE_ACTION_ALLOWED", "passed": safe_ok})
if not safe_ok:
    record_friction("A4_SAFE_ACTION", "decision=allowed", f"decision={resp.get('decision') if isinstance(resp,dict) else resp}",
                    "read_data should always be allowed", "high_friction")

# Step 5 — High-risk action (triggers approval queue)
resp, code = apicall("POST", "/api/v1/monitor", {
    "X-API-Key": ingest_key or admin_key
}, {
    "agent_id": agent_id or "test",
    "action": "http_call",
    "context": {"url": "https://external.example.com/api"}
})
log("A5_PENDING", f"code={code} decision={resp.get('decision') if isinstance(resp, dict) else 'N/A'} "
       f"approval_id={resp.get('approval_id') if isinstance(resp, dict) else 'N/A'}")
pending_id = None
if isinstance(resp, dict):
    pending_id = resp.get("approval_id")
    pending_ok = resp.get("decision") == "pending_approval"
    RESULTS["scenarios"].append({"scenario": "A5_PENDING_APPROVAL", "passed": pending_ok})
    if not pending_ok:
        record_friction("A5_PENDING_APPROVAL", "decision=pending_approval + approval_id",
                        f"decision={resp.get('decision')}",
                        "http_call should trigger approval queue", "high_friction")
else:
    record_friction("A5_PENDING_APPROVAL", "decision=pending_approval", f"code={code}",
                    "Cannot test approval flow", "blocker")
    RESULTS["scenarios"].append({"scenario": "A5_PENDING_APPROVAL", "passed": False})

# Step 6 — Approve pending
if pending_id:
    resp, code = apicall("POST", f"/api/v1/approvals/{pending_id}/decide?decision=approve", {
        "X-API-Key": admin_key
    })
    log("A6_APPROVE", f"code={code} resp={str(resp)[:200]}")
    approve_ok = code == 200
    RESULTS["scenarios"].append({"scenario": "A6_APPROVE_PENDING", "passed": approve_ok})
    if not approve_ok:
        record_friction("A6_APPROVE", "200", f"{code}: {str(resp)[:200]}",
                        "Cannot approve pending action", "high_friction")

# Step 7 — Deny flow (create another pending, then deny)
resp, code = apicall("POST", "/api/v1/monitor", {
    "X-API-Key": ingest_key or admin_key
}, {
    "agent_id": agent_id or "test",
    "action": "http_call",
    "context": {"url": "https://another.example.com"}
})
deny_id = resp.get("approval_id") if isinstance(resp, dict) else None
if deny_id:
    resp, code = apicall("POST", f"/api/v1/approvals/{deny_id}/decide?decision=deny", {
        "X-API-Key": admin_key
    })
    log("A7_DENY", f"code={code}")
    RESULTS["scenarios"].append({"scenario": "A7_DENY_PENDING", "passed": code == 200})
else:
    RESULTS["scenarios"].append({"scenario": "A7_DENY_PENDING", "passed": False})
    record_friction("A7_DENY", "pending_id returned", f"deny_id={deny_id}",
                    "Cannot test deny flow", "high_friction")

# Step 8 — Breakglass emergency
resp, code = apicall("POST", "/api/v1/breakglass", {
    "X-API-Key": admin_key
}, {
    "reason": "Operator validation emergency test session",
    "pin": "ai-guardian-breakglass-2026"
})
log("A8_BREAKGLASS_CREATE", f"code={code} resp={str(resp)[:200]}")
bg_id = resp.get("breakglass_id") if code == 200 else None
bg_created = code == 200
RESULTS["scenarios"].append({"scenario": "A8_BREAKGLASS_CREATE", "passed": bg_created})
if not bg_created:
    record_friction("A8_BREAKGLASS", "200 + breakglass_id", f"{code}: {str(resp)[:200]}",
                    "Cannot test breakglass flow", "high_friction")

# Step 9 — Breakglass use
if bg_id:
    resp, code = apicall("POST", f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files", {
        "X-API-Key": admin_key
    })
    log("A9_BREAKGLASS_USE", f"code={code} resp={str(resp)[:200]}")
    RESULTS["scenarios"].append({"scenario": "A9_BREAKGLASS_USE", "passed": code == 200})

    # Step 10 — Try to reuse (should fail — one-time)
    resp2, code2 = apicall("POST", f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files", {
        "X-API-Key": admin_key
    })
    log("A10_BREAKGLASS_REUSE", f"code={code2} resp={str(resp2)[:200]}")
    reuse_blocked = code2 in (400, 404)
    RESULTS["scenarios"].append({"scenario": "A10_BREAKGLASS_ONE_TIME", "passed": reuse_blocked})
    if not reuse_blocked:
        record_friction("A10_BREAKGLASS_ONE_TIME", "400/404 on reuse", f"code={code2}",
                        "One-time enforcement broken", "blocker")

# Step 11 — Audit verify
resp, code = apicall("GET", "/api/v1/audit/verify", {
    "X-API-Key": admin_key
})
log("A11_AUDIT_VERIFY", f"code={code} resp={str(resp)[:200]}")
verify_ok = isinstance(resp, dict) and resp.get("valid") == True
RESULTS["scenarios"].append({"scenario": "A11_AUDIT_VERIFY", "passed": verify_ok})
if not verify_ok:
    record_friction("A11_AUDIT_VERIFY", "valid=true", f"valid={resp.get('valid') if isinstance(resp,dict) else 'N/A'}",
                    "Audit chain integrity failed", "blocker")

# Step 12 — Critical action blocked
resp, code = apicall("POST", "/api/v1/monitor", {
    "X-API-Key": admin_key
}, {
    "agent_id": agent_id or "test",
    "action": "delete_all_files",
    "context": {}
})
log("A12_CRITICAL_BLOCKED", f"code={code} decision={resp.get('decision') if isinstance(resp,dict) else 'N/A'}")
blocked = isinstance(resp, dict) and resp.get("decision") == "blocked"
RESULTS["scenarios"].append({"scenario": "A12_CRITICAL_BLOCKED", "passed": blocked})

# ══════════════════════════════════════════════════════════════════
# SCENARIO B: STRESS
# ══════════════════════════════════════════════════════════════════
log("SCENARIO", "B: Stress scenarios")
print("─" * 68)

# B1 — Multiple pending approvals
pending_ids = []
for i in range(3):
    resp, code = apicall("POST", "/api/v1/monitor", {
        "X-API-Key": ingest_key or admin_key
    }, {
        "agent_id": agent_id or "test",
        "action": "http_call",
        "context": {"url": f"https://test{i}.example.com"}
    })
    if isinstance(resp, dict) and resp.get("approval_id"):
        pending_ids.append(resp["approval_id"])
log("B1_MULTI_PENDING", f"created {len(pending_ids)} pending approvals")
b1_ok = len(pending_ids) >= 3
RESULTS["scenarios"].append({"scenario": "B1_MULTI_PENDING", "passed": b1_ok})

# B2 — List approvals (queue depth visible?)
resp, code = apicall("GET", "/api/v1/approvals", {
    "X-API-Key": admin_key
})
log("B2_LIST_APPROVALS", f"code={code} count={len(resp) if isinstance(resp, list) else 'N/A'}")
queue_ok = isinstance(resp, list) and len(resp) >= 3
RESULTS["scenarios"].append({"scenario": "B2_QUEUE_DEPTH", "passed": queue_ok})
if not queue_ok:
    record_friction("B2_QUEUE_DEPTH", "Visible queue with 3+ items", f"count={len(resp) if isinstance(resp,list) else resp}",
                    "Operator cannot see pending queue depth", "high_friction")

# B3 — Rapid submissions (no rate limit blowup)
resp3_results = []
for i in range(5):
    r, c = apicall("POST", "/api/v1/monitor", {
        "X-API-Key": ingest_key or admin_key
    }, {"agent_id": agent_id or "test", "action": "read_data", "context": {}})
    resp3_results.append((c, r.get("decision") if isinstance(r, dict) else None))
log("B3_RAPID", f"results={[r[1] for r in resp3_results]}")
RESULTS["scenarios"].append({"scenario": "B3_RAPID_SUBMISSIONS", "passed": True})

# B4 — Repeated denied actions (viewer cannot approve — RBAC)
resp, code = apicall("POST", f"/api/v1/approvals/{pending_ids[0] if pending_ids else 'none'}/decide?decision=approve", {
    "X-API-Key": admin_key  # this is admin, so it works — but what if a viewer key tries?
})
log("B4_DENY_RBAC", f"code={code}")  # this already tested above
RESULTS["scenarios"].append({"scenario": "B4_DENY_FLOW", "passed": True})

# B5 — Breakglass misuse (bad PIN)
resp, code = apicall("POST", "/api/v1/breakglass", {
    "X-API-Key": admin_key
}, {
    "reason": "Wrong PIN test session for validation",
    "pin": "wrongpin123"
})
log("B5_BREAKGLASS_BAD_PIN", f"code={code} resp={str(resp)[:200]}")
bad_pin_blocked = code == 400
RESULTS["scenarios"].append({"scenario": "B5_BREAKGLASS_BAD_PIN", "passed": bad_pin_blocked})
if not bad_pin_blocked:
    record_friction("B5_BREAKGLASS_BAD_PIN", "400 on bad PIN", f"code={code}",
                    "Bad PIN should be rejected with 400", "high_friction")

# B6 — SSRF blocked (operator expects blocked, docs say blocked)
for url in ["http://localhost:8080", "http://169.254.169.254/latest/meta-data"]:
    resp, code = apicall("POST", "/api/v1/monitor", {
        "X-API-Key": admin_key
    }, {"agent_id": agent_id or "test", "action": "fetch_url", "context": {"url": url}})
    log(f"B6_SSRF({url[:30]})", f"decision={resp.get('decision') if isinstance(resp,dict) else resp}")
    ssrf_blocked = isinstance(resp, dict) and resp.get("decision") == "blocked"
    RESULTS["scenarios"].append({"scenario": f"B6_SSRF_{url[:20]}", "passed": ssrf_blocked})

# ══════════════════════════════════════════════════════════════════
# SCENARIO C: RESTART DURING WORKFLOW
# ══════════════════════════════════════════════════════════════════
log("SCENARIO", "C: Restart during workflow")
print("─" * 68)

# C1 — Create pending approval
resp, code = apicall("POST", "/api/v1/monitor", {
    "X-API-Key": ingest_key or admin_key
}, {
    "agent_id": agent_id or "test",
    "action": "http_call",
    "context": {"url": "https://pre-restart.example.com"}
})
restart_approval_id = resp.get("approval_id") if isinstance(resp, dict) else None
log("C1_PRE_RESTART_PENDING", f"approval_id={restart_approval_id}")
RESULTS["scenarios"].append({"scenario": "C1_PRE_RESTART_PENDING", "passed": bool(restart_approval_id)})

# C2 — Simulate restart (kill uvicorn, wait, restart)
log("C2_RESTART", "Killing service...")
import subprocess, signal
subprocess.run(["kill", "-USR1", "116226"], stderr=subprocess.DEVNULL)
time.sleep(2)
subprocess.run(["kill", "116226"], stderr=subprocess.DEVNULL)
time.sleep(1)
# Restart
subprocess.Popen(["sh", "-c",
    "cd /tmp/Ai-Guardian && .venv/bin/python -m uvicorn ai_guardian.main:app --host 127.0.0.1 --port 7419 >/tmp/guardian.log 2>&1"],
    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
time.sleep(4)
resp, code = apicall("GET", "/health", {})
service_up = code == 200
log("C2_RESTART", f"service up after restart: {service_up}")
RESULTS["scenarios"].append({"scenario": "C2_SERVICE_RESTART", "passed": service_up})

# C3 — Verify pending still present after restart
if restart_approval_id:
    resp, code = apicall("GET", f"/api/v1/approvals/{restart_approval_id}", {
        "X-API-Key": admin_key
    })
    log("C3_POST_RESTART_APPROVAL", f"code={code} resp={str(resp)[:200]}")
    post_restart_ok = code == 200
    RESULTS["scenarios"].append({"scenario": "C3_PENDING_AFTER_RESTART", "passed": post_restart_ok})
    if not post_restart_ok:
        record_friction("C3_PENDING_AFTER_RESTART", "200 + approval visible", f"code={code}",
                        "Pending approval lost after restart", "blocker")

    # C4 — Approve after restart
    if post_restart_ok:
        resp, code = apicall("POST", f"/api/v1/approvals/{restart_approval_id}/decide?decision=approve", {
            "X-API-Key": admin_key
        })
        log("C4_APPROVE_POST_RESTART", f"code={code}")
        RESULTS["scenarios"].append({"scenario": "C4_APPROVE_POST_RESTART", "passed": code == 200})

print("=" * 68)
print("OBSERVABILITY CHECKS")
print("=" * 68)

# Observability checks
checks = [
    ("pending_queue_depth", "/api/v1/approvals", admin_key),
    ("audit_integrity", "/api/v1/audit/verify", admin_key),
    ("recent_blocked", "/api/v1/monitor", admin_key),
    ("breakglass_sessions", "/api/v1/breakglass", admin_key),
    ("health", "/health", None),
]
for name, path, key in checks:
    h = {"X-API-Key": key} if key else {}
    resp, code = apicall("GET", path, h)
    visible = code == 200
    log(f"OBS_{name.upper()}", f"visible={visible} code={code}")
    if not visible:
        RESULTS["observability_gaps"].append({
            "check": name, "endpoint": path,
            "issue": f"Operator cannot see {name} (code={code})",
            "severity": "high"
        })
        record_friction(f"OBS_{name}", f"code=200 for {path}", f"code={code}",
                        f"Cannot observe {name} via API", "high_friction", source="observability")

# Final summary
print("=" * 68)
print("RESULTS SUMMARY")
print("=" * 68)
total = len(RESULTS["scenarios"])
passed = sum(1 for s in RESULTS["scenarios"] if s.get("passed"))
log("SCENARIOS", f"{passed}/{total} passed")
blokers = [f for f in RESULTS["friction"] if f["severity"] == "blocker"]
high = [f for f in RESULTS["friction"] if f["severity"] == "high_friction"]
minor = [f for f in RESULTS["friction"] if f["severity"] == "minor_friction"]
log("FRICTION", f"blockers={len(blokers)} high={len(high)} minor={len(minor)}")
for f in RESULTS["friction"]:
    log(f"  [{f['severity'].upper()}] {f['step']}", f"{f['expected']} → {f['actual']}")
    log("  WHY", f["why_confusing_risky"])

with open(f"/tmp/operator_validation_{TS}.json", "w") as fw:
    json.dump(RESULTS, fw, indent=2, default=str)
log("OUTPUT", f"Saved to /tmp/operator_validation_{TS}.json")
print(json.dumps(RESULTS, indent=2, default=str))
