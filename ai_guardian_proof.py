#!/usr/bin/env python3
"""
Ai-Guardian — Adversarial Proof Package
Phase 4 Enforcement — Single-run verification

Artifacts:
  ai_guardian_proof.py        — this file (primary proof)
  ai_guardian_proof_curl.sh  — curl equivalent (manual smoke test)

Run:
  .venv/bin/python3 ai_guardian_proof.py

Checks (7 categories, 56 steps):
  1. Auth path          — key creation, /me role, invalid/missing key
  2. Enforcement path   — http_call → pending_approval
  3. Approval path      — approve once, double-approve rejected
  4. Negative path      — delete_all_files blocked
  5. Audit completeness — all decision types logged, taxonomy printed
  6. SSRF protection    — internal URLs blocked
  7. Replay safety      — revoked/used breakglass fails, double-deny

Each step: step | expected | actual | pass/fail
"""

from __future__ import annotations
import uuid
import subprocess
import os

import requests

BASE_URL = "http://127.0.0.1:7419"
BOOT_KEY = "dev-guardian-key"

PASS: list[str] = []
FAIL: list[str] = []


# ── Git info ──────────────────────────────────────────────────────────
def git_info() -> tuple[str, str]:
    try:
        branch = subprocess.check_output(
            ["git", "-C", "/tmp/Ai-Guardian", "rev-parse", "--abbrev-ref", "HEAD"],
            text=True,
        ).strip()
        sha = subprocess.check_output(
            ["git", "-C", "/tmp/Ai-Guardian", "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip()
        return branch, sha
    except Exception:
        return "unknown", "unknown"


# ── Mask helpers ──────────────────────────────────────────────────────
def mask(s: str, show: int = 8) -> str:
    """Show first `show` chars + '...' + last 4 chars of a key/ID."""
    if not s or len(s) < show + 8:
        return f"{s[:show]}...???"
    return f"{s[:show]}...{s[-4:]}"


# ── Check helpers ──────────────────────────────────────────────────────
def check(label: str, expected: str, actual: str) -> bool:
    if expected == "4xx":
        ok = actual.startswith("4") and " " not in actual.split(":")[0]
    else:
        ok = str(actual).lower() == str(expected).lower()
    icon = "✅" if ok else "❌"
    print(f"  {icon} [{label}]")
    print(f"       EXPECTED: {expected}")
    print(f"       ACTUAL:   {actual}")
    (PASS if ok else FAIL).append(label)
    return ok


def check_true(label: str, expected: str, actual) -> bool:
    ok = bool(actual)
    icon = "✅" if ok else "❌"
    print(f"  {icon} [{label}]")
    print(f"       EXPECTED: {expected}")
    print(f"       ACTUAL:   {actual}")
    (PASS if ok else FAIL).append(label)
    return ok


def check_status(label: str, expected_code: int, actual_code: int,
                body: str = "") -> bool:
    ok = actual_code == expected_code
    actual = str(actual_code)
    if body:
        actual += f" | {body[:80]}"
    icon = "✅" if ok else "❌"
    print(f"  {icon} [{label}]")
    print(f"       EXPECTED status: {expected_code}")
    print(f"       ACTUAL status:   {actual}")
    (PASS if ok else FAIL).append(label)
    return ok


def stop_on_fail(ok: bool, where: str):
    if not ok:
        print(f"\n⛔ STOPPED at: {where}")
        for f in FAIL:
            print(f"  ❌ {f}")
        print(f"\n{len(PASS)} PASSED / {len(FAIL)} FAILED")
        import sys
        sys.exit(1)


def summary():
    print("\n" + "=" * 72)
    print(f"  PASSED: {len(PASS)}")
    print(f"  FAILED: {len(FAIL)}")
    for f in FAIL:
        print(f"    ❌ {f}")
    print("=" * 72)

    # Observed vs Expected table
    print("\n\n" + "═" * 72)
    print("  OBSERVED vs EXPECTED TABLE")
    print("═" * 72)
    for s in PASS:
        print(f"  ✅  {s}")
    for f in FAIL:
        print(f"  ❌  {f}")
    print("═" * 72)
    print(f"  TOTAL: {len(PASS)} PASSED / {len(FAIL)} FAILED")
    print("═" * 72)


# ── HTTP helpers ────────────────────────────────────────────────────────

def bootstrap() -> tuple[str, str]:
    """Bootstrap tenant with unique slug. Returns (admin_key, tenant_id)."""
    slug = f"ten-proof-{uuid.uuid4().hex[:8]}"
    r = requests.post(
        f"{BASE_URL}/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": BOOT_KEY},
        json={"name": "Proof Tenant", "slug": slug,
              "contact_email": "phil@proof.test"},
    )
    if r.status_code != 200:
        print(f"  ❌ BOOTSTRAP FAILED {r.status_code}: {r.text}")
        import sys
        sys.exit(1)
    data = r.json()
    return data["api_key"], slug


def create_key(admin_key: str, name: str, role: str) -> tuple[str | None, int]:
    """Create a subordinate key. Returns (plaintext_key, status_code)."""
    r = requests.post(
        f"{BASE_URL}/api/v1/api-keys",
        headers={"x-api-key": admin_key},
        params={"name": name, "role": role},
    )
    if r.status_code != 200:
        return None, r.status_code
    return r.json().get("api_key"), r.status_code


def monitor(key: str, action: str,
           source_url: str | None = None) -> tuple[dict, int]:
    body = {"agent_id": "agt_proof", "action": action, "context": {}}
    if source_url:
        body["source_url"] = source_url
    r = requests.post(f"{BASE_URL}/api/v1/monitor",
                      headers={"x-api-key": key}, json=body)
    return r.json(), r.status_code


# ══════════════════════════════════════════════════════════════════
# PROOF 1 — AUTH PATH
# ══════════════════════════════════════════════════════════════════

def proof1(admin_key: str) -> tuple[str, str]:
    """Bootstrap admin, create ingest+viewer, prove /me returns api_key.role."""
    print("\n── [PROOF 1] AUTH PATH ───────────────────────────────────────")

    # 1a: create ingest key
    ingest_key, sc = create_key(admin_key, "IngestWorker", "ingest")
    ok = check_status("create ingest key", 200, sc,
                      "" if ingest_key else "key missing")
    stop_on_fail(ok, "proof1: ingest key creation")
    ok = check_true("ingest key non-null", "non-null", ingest_key)
    stop_on_fail(ok, "proof1: ingest key non-null")
    print(f"       INGEST_KEY: {mask(ingest_key)}")

    # 1b: create viewer key
    viewer_key, sc = create_key(admin_key, "ViewerWorker", "viewer")
    ok = check_status("create viewer key", 200, sc,
                      "" if viewer_key else "key missing")
    stop_on_fail(ok, "proof1: viewer key creation")
    ok = check_true("viewer key non-null", "non-null", viewer_key)
    stop_on_fail(ok, "proof1: viewer key non-null")
    print(f"       VIEWER_KEY: {mask(viewer_key)}")

    # 1c: ingest /me → api_key.role == "ingest"
    r = requests.get(f"{BASE_URL}/api/v1/me",
                     headers={"x-api-key": ingest_key})
    d = r.json()
    role = d.get("api_key", {}).get("role", None)
    ok = check("ingest /me → api_key.role == 'ingest'",
               "ingest", str(role))
    stop_on_fail(ok, "proof1: ingest /me role")

    # 1d: viewer /me → api_key.role == "viewer"
    r = requests.get(f"{BASE_URL}/api/v1/me",
                     headers={"x-api-key": viewer_key})
    d = r.json()
    role = d.get("api_key", {}).get("role", None)
    ok = check("viewer /me → api_key.role == 'viewer'",
               "viewer", str(role))
    stop_on_fail(ok, "proof1: viewer /me role")

    # 1e: bad key → 401
    r = requests.get(f"{BASE_URL}/api/v1/me",
                      headers={"x-api-key": "bad_key_xyz"})
    ok = check("invalid key → 401", "401", str(r.status_code))
    stop_on_fail(ok, "proof1: invalid key")

    # 1f: no key → 422
    r = requests.get(f"{BASE_URL}/api/v1/me")
    ok = check("missing key → 422", "422", str(r.status_code))
    stop_on_fail(ok, "proof1: missing key")

    return ingest_key, viewer_key


# ══════════════════════════════════════════════════════════════════
# PROOF 2 — ENFORCEMENT PATH
# ══════════════════════════════════════════════════════════════════

def proof2(admin_key: str, ingest_key: str, viewer_key: str) -> str:
    """Ingest submits http_call → pending_approval + approval_id."""
    print("\n── [PROOF 2] ENFORCEMENT PATH ───────────────────────────────")
    print(f"       INGEST_KEY: {mask(ingest_key)}")
    print(f"       VIEWER_KEY: {mask(viewer_key)}")

    # 2a: ingest + http_call → pending_approval
    d, sc = monitor(ingest_key, "http_call")
    ok = check("ingest+http_call → decision == 'pending_approval'",
               "pending_approval", d.get("decision", "MISSING"))
    stop_on_fail(ok, "proof2: enforcement decision")
    aid = d.get("approval_id")
    ok = check_true("ingest+http_call → approval_id non-null",
                    "non-null string", aid)
    stop_on_fail(ok, "proof2: approval_id")
    ok = check("ingest+http_call → risk_score == 65",
               "65", str(d.get("risk_score", "MISSING")))
    stop_on_fail(ok, "proof2: risk score")
    print(f"       APPROVAL_ID: {mask(str(aid))}")

    # 2b: admin + external_api_call → pending_approval
    d, sc = monitor(admin_key, "external_api_call")
    ok = check("admin+external_api_call → decision == 'pending_approval'",
               "pending_approval", d.get("decision", "MISSING"))
    stop_on_fail(ok, "proof2: admin external_api_call")

    # 2c: viewer + read_logs → RBAC block (200+blocked, not 401)
    d, sc = monitor(viewer_key, "read_logs")
    ok = check("viewer+read_logs → status=200 AND decision=blocked",
               "200+blocked", f"{sc}+{d.get('decision','MISSING')}")
    stop_on_fail(ok, "proof2: viewer RBAC block")

    return str(aid)


# ══════════════════════════════════════════════════════════════════
# PROOF 3 — APPROVAL PATH
# ══════════════════════════════════════════════════════════════════

def proof3(admin_key: str, approval_id: str) -> None:
    """Admin approves once; second approval rejected."""
    print("\n── [PROOF 3] APPROVAL PATH ──────────────────────────────────")
    print(f"       ADMIN_KEY:  {mask(admin_key)}")
    print(f"       APPROVAL_ID: {mask(approval_id)}")

    # 3a: admin approves → approved
    r = requests.post(
        f"{BASE_URL}/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    d = r.json()
    ok = check("admin approves → status == 'approved'",
               "approved", d.get("status", "MISSING"))
    stop_on_fail(ok, "proof3: approve status")
    ok = check_true("decided_by non-null", "non-null", d.get("decided_by"))
    stop_on_fail(ok, "proof3: decided_by")
    print(f"       APPROVAL_ID: {mask(approval_id)} (first approve)")

    # 3b: GET /approvals → 200
    r = requests.get(f"{BASE_URL}/api/v1/approvals",
                     headers={"x-api-key": admin_key})
    ok = check("GET /approvals → 200", "200", str(r.status_code))
    stop_on_fail(ok, "proof3: list approvals")

    # 3c: second approval of same ID → rejected
    r = requests.post(
        f"{BASE_URL}/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    ok = check("double-approve → 4xx (no re-execution)",
               "4xx", f"{r.status_code}: {r.json().get('detail', '?')}")
    stop_on_fail(ok, "proof3: double-approve")
    print(f"       APPROVAL_ID: {mask(approval_id)} (second approve — REJECTED)")


# ══════════════════════════════════════════════════════════════════
# PROOF 4 — NEGATIVE PATH
# ══════════════════════════════════════════════════════════════════

def proof4(admin_key: str, ingest_key: str, viewer_key: str) -> None:
    """delete_all_files blocked for admin, ingest, viewer."""
    print("\n── [PROOF 4] NEGATIVE PATH ──────────────────────────────────")

    for key, label in [(admin_key, "admin"), (ingest_key, "ingest"),
                       (viewer_key, "viewer")]:
        d, sc = monitor(key, "delete_all_files")
        ok = check(f"{label}+delete_all_files → decision == 'blocked'",
                   "blocked", d.get("decision", "MISSING"))
        stop_on_fail(ok, f"proof4: {label} critical block")

    d, sc = monitor(admin_key, "exec_code")
    ok = check("admin+exec_code → decision == 'blocked'",
               "blocked", d.get("decision", "MISSING"))
    stop_on_fail(ok, "proof4: exec_code block")


# ══════════════════════════════════════════════════════════════════
# PROOF 5 — AUDIT COMPLETENESS
# ══════════════════════════════════════════════════════════════════

def proof5(admin_key: str) -> None:
    """Force all audit event types; print taxonomy."""
    print("\n── [PROOF 5] AUDIT COMPLETENESS ─────────────────────────────")

    # 5a: read_logs → allowed
    d, sc = monitor(admin_key, "read_logs")
    ok = check("read_logs → decision == 'allowed'",
               "allowed", d.get("decision", "MISSING"))
    stop_on_fail(ok, "proof5: allowed entry")

    # 5b: exec_code → blocked
    d, sc = monitor(admin_key, "exec_code")
    ok = check("exec_code → decision == 'blocked'",
               "blocked", d.get("decision", "MISSING"))
    stop_on_fail(ok, "proof5: blocked entry")

    # 5c: send_webhook → pending → denied
    d, sc = monitor(admin_key, "send_webhook")
    aid = d.get("approval_id", "MISSING")
    r = requests.post(
        f"{BASE_URL}/api/v1/approvals/{aid}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )
    ok = check("deny pending → status == 'denied'",
               "denied", r.json().get("status", "MISSING"))
    stop_on_fail(ok, "proof5: deny entry")

    # 5d: breakglass create
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={"reason": "adversarial verification test session",
              "duration_minutes": 5, "pin": "ai-guardian-breakglass-2026"},
    )
    bg_id = r.json().get("breakglass_id", "")
    ok = check_true("breakglass create → breakglass_id non-null",
                    "non-null string", bg_id)
    stop_on_fail(ok, "proof5: bg create")
    print(f"       BREAKGLASS_ID: {mask(bg_id)}")

    # 5e: breakglass use
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    ok = check("breakglass use → status == 'used'",
               "used", r.json().get("status", "MISSING"))
    stop_on_fail(ok, "proof5: bg use")

    # 5f: breakglass revoke
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass/{bg_id}/revoke",
        headers={"x-api-key": admin_key},
    )
    ok = check("breakglass revoke → status == 'revoked'",
               "revoked", r.json().get("status", "MISSING"))
    stop_on_fail(ok, "proof5: bg revoke")

    # 5g: GET /audit/logs — print taxonomy
    r = requests.get(f"{BASE_URL}/api/v1/audit/logs",
                     headers={"x-api-key": admin_key})
    logs = r.json()
    decisions = {e["decision"] for e in logs}
    actions = {e["action"] for e in logs}

    print(f"\n  Raw audit entries ({len(logs)}):")
    for e in logs:
        print(f"    action={e['action']!s:55}  decision={e['decision']}")

    print(f"\n  Decisions: {sorted(decisions)}")
    print(f"  Actions:    {sorted(actions)}")

    required_decisions = [
        "allowed", "blocked", "pending_approval",
        "approve", "deny", "breakglass_used",
    ]
    for dec in required_decisions:
        ok = check(f"audit has decision={dec}",
                   "present",
                   "PRESENT" if dec in decisions else "MISSING")
        stop_on_fail(ok, f"proof5: decision={dec}")

    required_actions = [
        "breakglass_create",
        "breakglass_override:delete_all_files",
        "breakglass_revoke",
    ]
    for act in required_actions:
        ok = check(f"audit has action={act}",
                   "present",
                   "PRESENT" if act in actions else "MISSING")
        stop_on_fail(ok, f"proof5: action={act}")

    # 5h: audit verify
    r = requests.get(f"{BASE_URL}/api/v1/audit/verify",
                     headers={"x-api-key": admin_key})
    d = r.json()
    ok = check("audit verify → valid == True", "True", str(d.get("valid", False)))
    stop_on_fail(ok, "proof5: audit verify")
    ok = check("audit verify → errors == []",
               "[]", str(d.get("errors", ["has errors"])))
    stop_on_fail(ok, "proof5: audit errors")


# ══════════════════════════════════════════════════════════════════
# PROOF 6 — SSRF PROTECTION
# ══════════════════════════════════════════════════════════════════

def proof6(admin_key: str) -> None:
    """Internal/metadata URLs → blocked."""
    print("\n── [PROOF 6] SSRF PROTECTION ───────────────────────────────")

    cases = [
        ("http://localhost:6379",            "localhost"),
        ("http://127.0.0.1:22",              "127.0.0.1"),
        ("http://169.254.169.254/",          "169.254.169.254"),
        ("http://[::1]:22/",                "IPv6 loopback [::1]"),
        ("http://metadata.google.internal/", "metadata.google.internal"),
    ]

    for url, label in cases:
        d, sc = monitor(admin_key, "fetch_url", source_url=url)
        ok = check(f"SSRF {label} → decision == 'blocked'",
                   "blocked", d.get("decision", "MISSING"))
        stop_on_fail(ok, f"proof6: SSRF {label}")
        ok = check(f"SSRF {label} → risk_score == 100",
                   "100", str(d.get("risk_score", "MISSING")))
        stop_on_fail(ok, f"proof6: SSRF {label} risk")


# ══════════════════════════════════════════════════════════════════
# PROOF 7 — REPLAY SAFETY
# ══════════════════════════════════════════════════════════════════

def proof7(admin_key: str) -> None:
    """Revoked breakglass fails, one-time breakglass reuse fails."""
    print("\n── [PROOF 7] REPLAY SAFETY ─────────────────────────────────")

    # 7a: double-approve idempotent
    d, sc = monitor(admin_key, "external_api_call")
    aid = str(d.get("approval_id", "MISSING"))
    r = requests.post(
        f"{BASE_URL}/api/v1/approvals/{aid}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    ok = check("first approve → status == 'approved'",
               "approved", r.json().get("status", "MISSING"))
    stop_on_fail(ok, "proof7: first approve")
    r = requests.post(
        f"{BASE_URL}/api/v1/approvals/{aid}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    ok = check("double-approve → 4xx",
               "4xx", f"{r.status_code}: {r.json().get('detail', '?')}")
    stop_on_fail(ok, "proof7: double-approve")

    # 7b: revoked breakglass → fails
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={"reason": "replay safety test session required here",
              "duration_minutes": 5, "pin": "ai-guardian-breakglass-2026"},
    )
    bg2 = r.json().get("breakglass_id", "MISSING")
    print(f"       BREAKGLASS_ID (revoked test): {mask(bg2)}")
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass/{bg2}/revoke",
        headers={"x-api-key": admin_key},
    )
    ok = check("revoke breakglass → status == 'revoked'",
               "revoked", r.json().get("status", "MISSING"))
    stop_on_fail(ok, "proof7: revoke breakglass")
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass/{bg2}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    ok = check("use revoked breakglass → 4xx",
               "4xx", f"{r.status_code}: {r.json().get('detail', '?')}")
    stop_on_fail(ok, "proof7: use revoked breakglass")

    # 7c: one-time breakglass reuse
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={"reason": "one time use breakglass session for test",
              "duration_minutes": 5, "pin": "ai-guardian-breakglass-2026"},
    )
    bg3 = r.json().get("breakglass_id", "MISSING")
    print(f"       BREAKGLASS_ID (one-time test): {mask(bg3)}")
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass/{bg3}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    ok = check("first use of bg3 → status == 'used'",
               "used", r.json().get("status", "MISSING"))
    stop_on_fail(ok, "proof7: first bg3 use")
    r = requests.post(
        f"{BASE_URL}/api/v1/breakglass/{bg3}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    ok = check("second use of bg3 → 4xx (one-time)",
               "4xx", f"{r.status_code}: {r.json().get('detail', '?')}")
    stop_on_fail(ok, "proof7: bg3 reuse")

    # 7d: double-deny idempotent
    d, sc = monitor(admin_key, "send_webhook")
    aid2 = str(d.get("approval_id", "MISSING"))
    r = requests.post(
        f"{BASE_URL}/api/v1/approvals/{aid2}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )
    ok = check("first deny → status == 'denied'",
               "denied", r.json().get("status", "MISSING"))
    stop_on_fail(ok, "proof7: first deny")
    r = requests.post(
        f"{BASE_URL}/api/v1/approvals/{aid2}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )
    ok = check("double-deny → 4xx",
               "4xx", f"{r.status_code}")
    stop_on_fail(ok, "proof7: double-deny")


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    import sys
    branch, sha = git_info()

    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║  Ai-Guardian — Adversarial Proof Package                           ║")
    print("║  Phase 4 Enforcement — Single-run verification                    ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(f"  Branch: {branch}")
    print(f"  Commit: {sha}")
    print(f"  Base:   {BASE_URL}\n")

    # Preflight: verify server is up
    r = requests.get(f"{BASE_URL}/health", timeout=5)
    if r.status_code != 200:
        print(f"❌ Server not responding: {r.status_code}")
        sys.exit(1)
    print(f"  ✅ Server health: {r.json()}\n")

    # 1. Bootstrap tenant with unique slug
    print("── [SETUP] Bootstrap tenant ─────────────────────────────────────────")
    admin_key, slug = bootstrap()
    print(f"  Tenant slug:   {slug}")
    print(f"  ADMIN_KEY:  {mask(admin_key)}\n")

    # 2-4. Auth path
    ingest_key, viewer_key = proof1(admin_key)

    # 5. Enforcement path
    approval_id = proof2(admin_key, ingest_key, viewer_key)

    # 6-7. Approval path
    proof3(admin_key, approval_id)

    # 8. Negative path
    proof4(admin_key, ingest_key, viewer_key)

    # 9. Audit completeness + breakglass reuse/revoke checks
    proof5(admin_key)

    # 10. SSRF protection
    proof6(admin_key)

    # 11. Replay safety
    proof7(admin_key)

    # 12. Summary + table
    summary()
    print("\n✅ ALL PROOFS PASSED — Phase 4 Enforcement verified")


if __name__ == "__main__":
    main()
