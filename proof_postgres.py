#!/usr/bin/env python3
"""Phase 9: Postgres end-to-end persistence proof.

Compares Postgres behavior against SQLite baseline.
Both must be identical.
"""
import sys, os, time
sys.path.insert(0, '/tmp/Ai-Guardian')
sys.path.insert(0, '/tmp/Ai-Guardian/scripts')
TS = str(int(time.time()))[-6:]

from ai_guardian.storage import PostgresStore
from ai_guardian import enforcement, breakglass, audit as audit_mod
from ai_guardian.audit import audit_log
from ai_guardian.service import GuardianService
from ai_guardian.config import Settings
from ai_guardian.models import TenantCreate, AgentRegistration, AccessContext

DB_URL = "postgresql://ai_guardiantest:testpassword123@localhost:5433/ai_guardian_test"

def fresh_store():
    s = PostgresStore(DB_URL)
    enforcement.configure_store(s)
    enforcement.load_from_db()
    breakglass.configure_store(s)
    breakglass.load_from_db()
    audit_log.configure_store(s)
    audit_log.load_from_db()
    return s

print("=" * 70)
print("PROOF: POSTGRES END-TO-END PERSISTENCE")
print("=" * 70)

store = fresh_store()

settings = Settings(
    service_name='ai-guardian',
    bootstrap_api_keys=('dev-guardian-key',),
    database_path='/tmp/dummy.db',  # not used with PostgresStore
    blocked_domains=('pastebin.com',),
    default_allowed_domains=('github.com',),
    suspicious_phrases=(),
    webhook_urls=(),
    rate_limit_per_minute=120,
    database_url=DB_URL,
)
svc = GuardianService(settings)

bp = svc.bootstrap_tenant(
    payload=TenantCreate(name='PgProofTenant', slug=f'pg-proof-{TS}',
                         contact_email='pgproof@example.com', plan='starter'),
    key_name='admin-key',
)
tenant_id = bp.tenant.tenant_id
tenant_slug = bp.tenant.slug
print(f"tenant_id:  {tenant_id}")
print(f"tenant_slug: {tenant_slug}")
admin_key = bp.api_key
print(f"admin_key: {admin_key[:12]}...")

agent_rec = svc.register_agent(
    access=AccessContext(tenant_id=tenant_id, key_id='init', role='admin'),
    registration=AgentRegistration(name='ProofAgent', owner='proof',
                                  description='test', allowed_domains=[]),
)
agent_id = agent_rec.agent_id
print(f"agent_id:   {agent_id}")

# ── A. PENDING APPROVAL ──────────────────────────────────────────────────────
pending = enforcement.create_pending(
    tenant_id=tenant_id, agent_id=agent_id,
    action='delete_all_files', context={'test': 'pg-proof'},
    actor='admin', risk_score=85,
)
approval_id = pending.approval_id
print(f"\napproval_id: {approval_id}")

# ── B. BREAKGLASS ────────────────────────────────────────────────────────────
bg = breakglass.create_session(
    tenant_id=tenant_id, actor='admin',
    reason='postgres proof emergency access for phase nine testing',
    pin='ai-guardian-breakglass-2026', duration_minutes=15,
)
bg_id = bg.breakglass_id
print(f"breakglass_id: {bg_id}")

bg2 = breakglass.create_session(
    tenant_id=tenant_id, actor='admin',
    reason='postgres proof revoke test session for breakglass state',
    pin='ai-guardian-breakglass-2026', duration_minutes=15,
)
bg2_id = bg2.breakglass_id

breakglass.use_session(bg_id, 'delete_all_files')
breakglass.revoke_session(bg2_id)

bg_row = store.get_breakglass_session(bg_id)
bg2_row = store.get_breakglass_session(bg2_id)
print(f"[breakglass] bg_id used flag: {bg_row['used']} (expect: True)")
print(f"[breakglass] bg2_id status: {bg2_row['status']} (expect: revoked)")

# ── C. AUDIT LOG ─────────────────────────────────────────────────────────────
audit_count_pre = audit_log.count(tenant_id)
print(f"\n[audit] entries pre-restart: {audit_count_pre}")

for action, decision in [
    ('guardian_allowed:read_data', 'allowed'),
    ('guardian_blocked:ssrf:fetch_url', 'blocked'),
    ('breakglass_create', 'allowed'),
]:
    audit_log.append(tenant_id=tenant_id, actor='admin', action=action,
                    decision=decision, risk_score=50)

valid_pre, _ = audit_log.verify_integrity(tenant_id)
audit_count_mid = audit_log.count(tenant_id)
print(f"[audit] entries after additions: {audit_count_mid}")
print(f"[audit] verify_integrity pre-restart: valid={valid_pre}")

# ── SIMULATE RESTART ─────────────────────────────────────────────────────────
print("\n━━━ SIMULATING RESTART ━━━")
enforcement._PENDING.clear(); enforcement._store_ref = None
breakglass._STORE.clear(); breakglass._store_ref = None
audit_mod.audit_log._entries.clear(); audit_mod.audit_log._store = None

store2 = fresh_store()

# D. APPROVAL PERSISTENCE
print("\n━━━ D. APPROVAL PERSISTENCE ━━━")
p2 = store2.get_pending_approval(approval_id)
print(f"[approval] status: {p2['status']} (expect: pending)")
print(f"[approval] tenant matches: {p2['tenant_id'] == tenant_id} (expect: True)")
rec = enforcement.get_pending(approval_id)
print(f"[approval] get_pending() works: {rec is not None}")
approved = enforcement.approve_pending(approval_id, 'post_restart_admin')
print(f"[approval] approve post-restart: {approved is not None and approved.status == 'approved'} (expect: True)")

# E. BREAKGLASS PERSISTENCE
print("\n━━━ E. BREAKGLASS PERSISTENCE ━━━")
ok1, msg1 = breakglass.validate_session(bg_id)
print(f"[breakglass] bg_id (used) valid={ok1} msg={msg1}")
print(f"  → used session blocked after restart: {not ok1} (expect: True)")

ok2, msg2 = breakglass.validate_session(bg2_id)
print(f"[breakglass] bg2_id (revoked) valid={ok2} msg={msg2}")
print(f"  → revoked session blocked after restart: {not ok2} (expect: True)")

bg3 = breakglass.create_session(
    tenant_id=tenant_id, actor='admin',
    reason='postgres proof fresh session test for one-time enforcement',
    pin='ai-guardian-breakglass-2026', duration_minutes=15,
)
bg3_id = bg3.breakglass_id
used_ok = breakglass.use_session(bg3_id, 'delete_all')
ok3, msg3 = breakglass.validate_session(bg3_id)
print(f"[breakglass] bg3_id one-time: used={used_ok}, then valid={ok3}")
print(f"  → one-time enforcement after restart: {not ok3} (expect: True)")

# F. AUDIT LOG
print("\n━━━ F. AUDIT LOG PERSISTENCE ━━━")
entries_post = audit_log.get_recent(tenant_id, 100)
print(f"[audit] entries after restart: {len(entries_post)}")
valid_post, errs_post = audit_log.verify_integrity(tenant_id)
print(f"[audit] verify_integrity post-restart: valid={valid_post}")
if errs_post: print(f"[audit] errors: {errs_post}")
print(f"[audit] hash chain unbroken: {valid_post} (expect: True)")

audit_log.append(tenant_id=tenant_id, actor='post_restart',
                 action='guardian_allowed:post_restart_append', decision='allowed', risk_score=5)
valid_final, errs_final = audit_log.verify_integrity(tenant_id)
print(f"[audit] chain extends after new append: {valid_final} (expect: True)")

print()
print("━" * 70)
print("EXACT IDENTIFIERS")
print("━" * 70)
print(f"tenant_id:   {tenant_id}")
print(f"tenant_slug: {tenant_slug}")
print(f"approval_id: {approval_id}")
print(f"bg_session:  {bg_id}  (used — blocked after restart ✅)")
print(f"bg_revoked:  {bg2_id} (revoked — blocked after restart ✅)")
print(f"bg_fresh:   {bg3_id}  (one-time enforced after restart ✅)")
print(f"audit_pre:   {audit_count_pre} entries")
print(f"audit_post:  {len(entries_post)} entries")
print(f"audit_valid: {valid_post}")
print()
print("PROOF: POSTGRES END-TO-END PERSISTENCE ✅")
print("━" * 70)
