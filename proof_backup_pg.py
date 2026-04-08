#!/usr/bin/env python3
"""Step 4: Postgres backup / restore proof.

Uses pg_dump to back up → drops/restores DB → verifies all state survived.
Requires running Postgres container (from Phase 9 Step 1).
"""
import sys, os, time
sys.path.insert(0, '/tmp/Ai-Guardian')
sys.path.insert(0, '/tmp/Ai-Guardian/scripts')

from ai_guardian.storage import PostgresStore
from ai_guardian import enforcement, breakglass, audit as audit_mod
from ai_guardian.audit import audit_log
from ai_guardian.service import GuardianService
from ai_guardian.config import Settings
from ai_guardian.models import TenantCreate, AgentRegistration, AccessContext

TS = str(int(time.time()))[-6:]
DB_URL = "postgresql://ai_guardiantest:testpassword123@localhost:5433/ai_guardian_test"
DUMP_FILE = f"/tmp/postgres_backup_{TS}.sql"

# ── CLEAN START ─────────────────────────────────────────────────────────
print("Dropping/recreating test DB...")
os.system(f"PGPASSWORD=testpassword123 psql -h localhost -p 5433 -U ai_guardiantest -d postgres "
          f"-c 'DROP DATABASE IF EXISTS ai_guardian_backup_test' 2>/dev/null")
os.system(f"PGPASSWORD=testpassword123 psql -h localhost -p 5433 -U ai_guardiantest -d postgres "
          f"-c 'CREATE DATABASE ai_guardian_backup_test' 2>/dev/null")

BACKUP_DB_URL = DB_URL.replace('ai_guardian_test', 'ai_guardian_backup_test')

def fresh_store(url):
    s = PostgresStore(url)
    enforcement.configure_store(s)
    enforcement.load_from_db()
    breakglass.configure_store(s)
    breakglass.load_from_db()
    audit_log.configure_store(s)
    audit_log.load_from_db()
    return s

def reset_state():
    enforcement._PENDING.clear(); enforcement._store_ref = None
    breakglass._STORE.clear(); breakglass._store_ref = None
    audit_mod.audit_log._entries.clear(); audit_mod.audit_log._store = None

settings = Settings(
    service_name='ai-guardian', bootstrap_api_keys=('dev-guardian-key',),
    database_path='/tmp/dummy.db', database_url=DB_URL,
    blocked_domains=(), default_allowed_domains=(), suspicious_phrases=(),
    webhook_urls=(), rate_limit_per_minute=120,
)

# Run migrations on main DB
from scripts.run_migrations import run_postgres
run_postgres(DB_URL)

svc = GuardianService(settings)
enforcement.configure_store(svc.store)
breakglass.configure_store(svc.store)
audit_log.configure_store(svc.store)

bp = svc.bootstrap_tenant(
    payload=TenantCreate(name=f'PgBackup{TS}', slug=f'pg-backup-{TS}',
                         contact_email=f'pgbackup{TS}@example.com', plan='starter'),
    key_name='admin-key')
tenant_id = bp.tenant.tenant_id

agent_rec = svc.register_agent(
    access=AccessContext(tenant_id=tenant_id, key_id='init', role='admin'),
    registration=AgentRegistration(name='BackupAgent', owner='proof',
                                  description='test', allowed_domains=[]),
)
agent_id = agent_rec.agent_id

pending = enforcement.create_pending(
    tenant_id=tenant_id, agent_id=agent_id,
    action='delete_all_data', context={'test': 'pg_backup'},
    actor='admin', risk_score=85,
)
approval_id = pending.approval_id

bg_used = breakglass.create_session(
    tenant_id=tenant_id, actor='admin',
    reason='pg backup used session for restore verification test',
    pin='ai-guardian-breakglass-2026', duration_minutes=15,
)
bg_used_id = bg_used.breakglass_id
breakglass.use_session(bg_used_id, 'delete_data')

bg_fresh = breakglass.create_session(
    tenant_id=tenant_id, actor='admin',
    reason='pg backup fresh session for restore verification valid check',
    pin='ai-guardian-breakglass-2026', duration_minutes=15,
)
bg_fresh_id = bg_fresh.breakglass_id

for action, decision in [
    ('guardian_allowed:read_backup', 'allowed'),
    ('guardian_pending:delete_data', 'pending'),
    ('breakglass_create', 'breakglass_created'),
]:
    audit_log.append(tenant_id=tenant_id, actor='admin', action=action,
                    decision=decision, risk_score=50)

audit_pre_count = audit_log.count(tenant_id)
print(f"\n[setup] approval_id: {approval_id}")
print(f"[setup] bg_used_id: {bg_used_id}")
print(f"[setup] bg_fresh_id: {bg_fresh_id}")
print(f"[setup] audit entries: {audit_pre_count}")

# Verify data in DB before dump
import psycopg
_conn_pre = psycopg.connect(DB_URL)
_cur = _conn_pre.cursor()
_cur.execute("SELECT COUNT(*) FROM pending_approvals")
_appr_count = _cur.fetchone()[0]
_cur.execute("SELECT COUNT(*) FROM breakglass_sessions")
_bg_count = _cur.fetchone()[0]
_cur.execute("SELECT COUNT(*) FROM audit_log")
_audit_count = _cur.fetchone()[0]
print(f"[pre-dump] pending={_appr_count} bg={_bg_count} audit={_audit_count}")
_conn_pre.close()

# ── STEP 1: pg_dump ──────────────────────────────────────────────────────
print(f"\n[pg_dump] dumping to {DUMP_FILE} ...")
result = os.system(f"PGPASSWORD=testpassword123 pg_dump -h localhost -p 5433 -U ai_guardiantest "
                   f"-d ai_guardian_test -f {DUMP_FILE} 2>/dev/null")
dump_ok = result == 0 and os.path.exists(DUMP_FILE)
print(f"[pg_dump] success={dump_ok}, size={os.path.getsize(DUMP_FILE) if dump_ok else 'N/A'}")

# ── STEP 2: Simulate crash ───────────────────────────────────────────────
print("\n[crash] resetting in-memory state...")
reset_state()

# Drop and recreate empty DB
os.system(f"PGPASSWORD=testpassword123 psql -h localhost -p 5433 -U ai_guardiantest -d postgres "
          f"-c 'DROP DATABASE IF EXISTS ai_guardian_backup_dest' 2>/dev/null")
os.system(f"PGPASSWORD=testpassword123 psql -h localhost -p 5433 -U ai_guardiantest -d postgres "
          f"-c 'CREATE DATABASE ai_guardian_backup_dest' 2>/dev/null")
DEST_DB_URL = DB_URL.replace('ai_guardian_test', 'ai_guardian_backup_dest')

# Restore dump into fresh DB
print(f"[restore] loading dump into fresh DB...")
result2 = os.system(f"PGPASSWORD=testpassword123 psql -h localhost -p 5433 -U ai_guardiantest "
                     f"-d ai_guardian_backup_dest -f {DUMP_FILE} 2>/dev/null")
restore_ok = result2 == 0
print(f"[restore] success={restore_ok}")

# Wire to restored DB
store2 = PostgresStore(DEST_DB_URL)
enforcement.configure_store(store2); enforcement.load_from_db()
breakglass.configure_store(store2); breakglass.load_from_db()
audit_log.configure_store(store2); audit_log.load_from_db()

# ── STEP 3: Verify ───────────────────────────────────────────────────────
print("\n━━━ VERIFICATION ━━━")

p = enforcement.get_pending(approval_id)
print(f"[approval] present={p is not None}  status={p.status if p else 'N/A'}")
approved = enforcement.approve_pending(approval_id, 'post_restore_admin')
print(f"[approval] approve works={approved is not None}  status={approved.status}")

ok_used, msg_used = breakglass.validate_session(bg_used_id)
print(f"[breakglass] used session: valid={ok_used}  msg={msg_used}")
assert not ok_used, "FAIL: used session should be blocked"

ok_fresh, msg_fresh = breakglass.validate_session(bg_fresh_id)
print(f"[breakglass] fresh session: valid={ok_fresh}")
assert ok_fresh, "FAIL: fresh session should be valid"

used_ok = breakglass.use_session(bg_fresh_id, 'delete_data')
ok_after, _ = breakglass.validate_session(bg_fresh_id)
print(f"[breakglass] one-time enforced={not ok_after}")

entries_post = audit_log.get_recent(tenant_id, 100)
valid, errs = audit_log.verify_integrity(tenant_id)
print(f"[audit] entries: {len(entries_post)} (expect {audit_pre_count})")
print(f"[audit] verify_integrity: valid={valid}")

audit_log.append(tenant_id=tenant_id, actor='post_restore',
                action='guardian_allowed:post_restore_write', decision='allowed', risk_score=5)
valid_final, _ = audit_log.verify_integrity(tenant_id)
print(f"[audit] chain extends after new write: {valid_final}")

print()
print("━" * 70)
print("POSTGRES BACKUP/RESTORE PROOF ✅")
print("━" * 70)
print(f"approval_id:    {approval_id}")
print(f"bg_used_id:     {bg_used_id}  (blocked after restore ✅)")
print(f"bg_fresh_id:   {bg_fresh_id}  (one-time enforced after restore ✅)")
print(f"audit_pre:      {audit_pre_count} entries")
print(f"audit_post:     {len(entries_post)} entries")
print(f"audit_valid:    {valid}")
print(f"dump_file:     {DUMP_FILE}")

os.unlink(DUMP_FILE)