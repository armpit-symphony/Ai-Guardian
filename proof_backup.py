#!/usr/bin/env python3
"""Step 4: SQLite backup / restore proof.

Creates state → backs up DB file → deletes state → restores DB →
verifies all state survived with audit chain intact.
"""
import sys, os, shutil, tempfile
sys.path.insert(0, '/tmp/Ai-Guardian')
sys.path.insert(0, '/tmp/Ai-Guardian/scripts')

from scripts.run_migrations import run_sqlite
from ai_guardian.storage import SQLiteStore
from ai_guardian import enforcement, breakglass, audit as audit_mod
from ai_guardian.audit import audit_log
from ai_guardian.service import GuardianService
from ai_guardian.config import Settings
from ai_guardian.models import TenantCreate, AgentRegistration, AccessContext

ORIG_DB = "/tmp/backup_proof.db"
BACKUP_DB = "/tmp/backup_proof.backup.db"

# Clean start
for f in [ORIG_DB, BACKUP_DB]:
    if os.path.exists(f): os.unlink(f)

# Run migrations FIRST so all Phase 3/4/6 tables exist
run_sqlite(ORIG_DB)

# ── SETUP: Create live state ──────────────────────────────────────────────
settings = Settings(
    service_name='ai-guardian',
    bootstrap_api_keys=('dev-guardian-key',),
    database_path=ORIG_DB,
    database_url=None,
    blocked_domains=('pastebin.com',),
    default_allowed_domains=('github.com',),
    suspicious_phrases=(),
    webhook_urls=(),
    rate_limit_per_minute=120,
)
svc = GuardianService(settings)
# Wire enforcement/breakglass/audit to the service's store BEFORE creating state
enforcement.configure_store(svc.store)
breakglass.configure_store(svc.store)
audit_mod.audit_log.configure_store(svc.store)
bp = svc.bootstrap_tenant(
    payload=TenantCreate(name='BackupProof', slug='backup-proof',
                         contact_email='backup@example.com', plan='starter'),
    key_name='admin-key',
)
tenant_id = bp.tenant.tenant_id
admin_key = bp.api_key

agent_rec = svc.register_agent(
    access=AccessContext(tenant_id=tenant_id, key_id='init', role='admin'),
    registration=AgentRegistration(name='BackupAgent', owner='proof',
                                  description='test', allowed_domains=[]),
)
agent_id = agent_rec.agent_id

# Create pending approval
pending = enforcement.create_pending(
    tenant_id=tenant_id, agent_id=agent_id,
    action='delete_all_data', context={'test': 'backup'},
    actor='admin', risk_score=85,
)
approval_id = pending.approval_id

# Create breakglass (used + fresh)
bg_used = breakglass.create_session(
    tenant_id=tenant_id, actor='admin',
    reason='backup proof used session for restore test',
    pin='ai-guardian-breakglass-2026', duration_minutes=15,
)
bg_used_id = bg_used.breakglass_id
breakglass.use_session(bg_used_id, 'delete_data')

bg_fresh = breakglass.create_session(
    tenant_id=tenant_id, actor='admin',
    reason='backup proof fresh session for restore verification',
    pin='ai-guardian-breakglass-2026', duration_minutes=15,
)
bg_fresh_id = bg_fresh.breakglass_id

# Write audit entries
for action, decision in [
    ('guardian_allowed:read_backup', 'allowed'),
    ('guardian_pending:delete_data', 'pending'),
    ('breakglass_create', 'breakglass_created'),
]:
    audit_log.append(tenant_id=tenant_id, actor='admin', action=action,
                    decision=decision, risk_score=50)

audit_pre_count = audit_log.count(tenant_id)
print(f"[setup] approval_id: {approval_id}")
print(f"[setup] bg_used_id: {bg_used_id}")
print(f"[setup] bg_fresh_id: {bg_fresh_id}")
print(f"[setup] audit entries: {audit_pre_count}")

# ── DEBUG: inspect raw DB right after setup ─────────────────────────────
import sqlite3 as _sq
_setup_check = _sq.connect(ORIG_DB)
_setup_appr = _setup_check.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
_setup_bg = _setup_check.execute("SELECT COUNT(*) FROM breakglass_sessions").fetchone()[0]
_setup_audit = _setup_check.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
print(f"\n[setup-raw-db] pending={_setup_appr} bg={_setup_bg} audit={_setup_audit}")
_setup_check.close()

# ── STEP 1: Back up DB file ───────────────────────────────────────────────
shutil.copy2(ORIG_DB, BACKUP_DB)
print(f"\n[backup] copied {ORIG_DB} → {BACKUP_DB}")
print(f"[backup] backup file size: {os.path.getsize(BACKUP_DB)} bytes")

# ── STEP 1b: Verify data present BEFORE crash ───────────────────────────
import sqlite3 as _sq
_pre_check = _sq.connect(ORIG_DB)
_pre_count = _pre_check.execute("SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
_pre_bg = _pre_check.execute("SELECT COUNT(*) FROM breakglass_sessions").fetchone()[0]
_pre_audit = _pre_check.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
_pre_apr = _pre_check.execute(
    "SELECT approval_id, status FROM pending_approvals").fetchall()
_pre_bg_rows = _pre_check.execute(
    "SELECT breakglass_id, status, used FROM breakglass_sessions").fetchall()
print(f"[pre-crash] pending_approvals={_pre_count} breakglass_sessions={_pre_bg} audit_log={_pre_audit}")
print(f"[pre-crash] pending rows: {_pre_apr}")
print(f"[pre-crash] bg rows: {_pre_bg_rows}")
_pre_check.close()

# ── STEP 2: Simulate crash (wipe in-memory state + delete DB) ─────────────
enforcement._PENDING.clear(); enforcement._store_ref = None
breakglass._STORE.clear(); breakglass._store_ref = None
audit_mod.audit_log._entries.clear(); audit_mod.audit_log._store = None
os.unlink(ORIG_DB)
print("[crash] in-memory state wiped, DB file deleted")

# ── STEP 3: Restore from backup ───────────────────────────────────────────
shutil.copy2(BACKUP_DB, ORIG_DB)
print(f"[restore] {BACKUP_DB} → {ORIG_DB}")

# Run migrations (re-creates Phase 3-4 tables that exist in backup)
run_sqlite(ORIG_DB)

# Reload via fresh store
store2 = SQLiteStore(ORIG_DB)
enforcement.configure_store(store2); enforcement.load_from_db()
breakglass.configure_store(store2); breakglass.load_from_db()
audit_log.configure_store(store2); audit_log.load_from_db()

# ── STEP 4: Verify state ───────────────────────────────────────────────────
print("\n━━━ VERIFICATION ━━━")

# Debug: inspect restored DB
import sqlite3 as _sq
_conn_check = _sq.connect(ORIG_DB)
_tables = [r[0] for r in _conn_check.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
_approval_rows = _conn_check.execute(
    "SELECT COUNT(*) FROM pending_approvals").fetchone()[0]
print(f"[debug] DB tables: {_tables}")
print(f"[debug] pending_approvals rows: {_approval_rows}")
sample = _conn_check.execute(
    "SELECT approval_id, status, tenant_id FROM pending_approvals LIMIT 5").fetchall()
print(f"[debug] all pending_approvals: {sample}")
_conn_check.close()

# Direct store lookup
store2_debug = SQLiteStore(ORIG_DB)
row = store2_debug.get_pending_approval(approval_id)
print(f"[debug] store.get_pending_approval('{approval_id}'): {row}")
bg_row = store2_debug.get_breakglass_session(bg_used_id)
print(f"[debug] store.get_breakglass_session(bg_used_id): {bg_row}")

# A. Pending approval
p = enforcement.get_pending(approval_id)
print(f"[approval] present={p is not None}  status={p.status if p else 'N/A'}")
assert p is not None and p.status == 'pending', "FAIL: approval missing or wrong status"
approved = enforcement.approve_pending(approval_id, 'post_restore_admin')
print(f"[approval] approve works={approved is not None}  status={approved.status}")
assert approved.status == 'approved'

# B. Breakglass used session
ok_used, msg_used = breakglass.validate_session(bg_used_id)
print(f"[breakglass] used session: valid={ok_used}  msg={msg_used}")
assert not ok_used, "FAIL: used session should be blocked"

# C. Breakglass fresh session
ok_fresh, msg_fresh = breakglass.validate_session(bg_fresh_id)
print(f"[breakglass] fresh session: valid={ok_fresh}  msg={msg_fresh}")
assert ok_fresh, "FAIL: fresh session should be valid"
used_ok = breakglass.use_session(bg_fresh_id, 'delete_data')
ok_after_use, _ = breakglass.validate_session(bg_fresh_id)
print(f"[breakglass] one-time enforced={not ok_after_use}")
assert not ok_after_use, "FAIL: one-time use should block after first use"

# D. Audit log
entries_post = audit_log.get_recent(tenant_id, 100)
valid, errs = audit_log.verify_integrity(tenant_id)
print(f"[audit] entries after restore: {len(entries_post)}")
print(f"[audit] verify_integrity: valid={valid}  errors={errs}")
assert len(entries_post) == audit_pre_count, f"FAIL: audit count mismatch {len(entries_post)} != {audit_pre_count}"
assert valid, f"FAIL: audit chain broken: {errs}"

# E. New write after restore
audit_log.append(tenant_id=tenant_id, actor='post_restore',
                 action='guardian_allowed:post_restore_write', decision='allowed', risk_score=5)
valid_final, errs_final = audit_log.verify_integrity(tenant_id)
print(f"[audit] chain extends after new write: {valid_final}")

print()
print("━" * 70)
print("SQLITE BACKUP/RESTORE PROOF ✅")
print("━" * 70)
print(f"approval_id:     {approval_id}")
print(f"bg_used_id:      {bg_used_id}  (blocked after restore ✅)")
print(f"bg_fresh_id:    {bg_fresh_id}  (one-time enforced after restore ✅)")
print(f"audit_pre:       {audit_pre_count} entries")
print(f"audit_post:      {len(entries_post)} entries")
print(f"audit_valid:     {valid}")
print(f"backup_file:    {BACKUP_DB} ({os.path.getsize(BACKUP_DB)} bytes)")

# Cleanup
os.unlink(ORIG_DB); os.unlink(BACKUP_DB)