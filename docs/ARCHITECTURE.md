# Architecture

## System Overview

AI Guardian is a FastAPI service that intercepts agent actions, evaluates them against a policy engine, and returns enforcement decisions. All state is persisted to SQLite (or PostgreSQL) for restart safety.

```
┌─────────────┐     ┌──────────────────────────────────────────────────────┐
│  AI Agent   │────▶│  AI Guardian (FastAPI)                             │
│             │     │                                                      │
│             │◀────│  ┌─────────────────────────────────────────────┐   │
└─────────────┘     │  │  GuardianInterceptor.evaluate()               │   │
                     │  │                                              │   │
                     │  │  Step 0: Critical action blocklist          │   │
                     │  │         ↓                                    │   │
                     │  │  Step 1: RBAC (admin/ingest/viewer)         │   │
                     │  │         ↓                                    │   │
                     │  │  Step 2: Breakglass override check          │   │
                     │  │         ↓                                    │   │
                     │  │  Step 3: Policy + risk scoring                │   │
                     │  │         ↓                                    │   │
                     │  │  Step 4: Decision (allowed/blocked/pending)  │   │
                     │  └─────────────────────────────────────────────┘   │
                     │                                                      │
                     │  ┌──────────┐  ┌──────────────┐  ┌────────────┐  │
                     │  │ SQLite   │  │ Approval     │  │ Breakglass │  │
                     │  │ storage  │◀─│ Queue        │  │ Sessions   │  │
                     │  │          │  │ (pending_)   │  │            │  │
                     │  └──────────┘  └──────────────┘  └────────────┘  │
                     │           ↓            ↓                 ↓           │
                     │  ┌──────────────────────────────────────────────┐  │
                     │  │  ImmutableAuditLog (hash-chained entries)    │  │
                     │  └──────────────────────────────────────────────┘  │
                     └──────────────────────────────────────────────────────┘
```

---

## Components

### GuardianInterceptor

The single choke point. Every guarded action flows through `evaluate()`:

```
AccessContext + MonitorRequest → evaluate() → GuardianDecision
```

**Step 0 — Critical Blocklist**
Actions like `delete_all_files`, `exec_code`, `drop_database` are immediately blocked regardless of role.

**Step 1 — RBAC**
Only `admin` and `ingest` roles can submit actions. `viewer` cannot.

**Step 2 — Breakglass Override**
If a valid breakglass session ID is provided and the action is blocked/pending, the breakglass overrides the decision (one-time use).

**Step 3 — Policy + Risk Scoring**
- Network outbound calls → checked against `blocked_domains`
- Action category detection (file, network, code, database, system)
- Severity scoring from findings
- `risk_score` computed (0–100)

**Step 4 — Decision**
| risk_score | decision |
|---|---|
| < high_risk_threshold (65) | `allowed` |
| ≥ threshold (65) | `pending_approval` |
| Critical action | `blocked` |

---

### Enforcement (Approval Queue)

Persisted to `pending_approvals` table in SQLite.

```
create_pending() → DB write → in-memory cache update
approve_pending() → DB update → in-memory cache update
deny_pending()   → DB update → in-memory cache update
```

On startup: `load_from_db()` rebuilds the in-memory cache from SQLite.

---

### Breakglass

Persisted to `breakglass_sessions` table in SQLite.

Each session has:
- `status`: `active | used | expired | revoked`
- `used`: boolean (one-time enforcement)
- `actions_overridden`: JSON list of used actions

**Lifecycle:**
```
create_session()  → active (DB write)
  use_session()  → used=true, status=used (DB write) — one-time only
  revoke_session() → status=revoked (DB write)
  expiry         → status=expired (cleanup job)
```

On startup: `load_from_db()` restores all sessions including used/revoked state.

---

### Audit Log

Persisted to `audit_log` table in SQLite.

Hash chaining:
```
entry[n].prev_hash = entry[n-1].hash  (or GENESIS for first entry)
entry[n].hash = SHA256(canonical_json(entry[n] excluding 'id', 'hash'))
```

`verify_integrity()` recomputes each hash and checks chain links. Any tampering is detected.

On startup: `load_from_db()` restores all entries and the chain continues from the last entry.

---

### Storage (SQLiteStore)

All CRUD operations for: `tenants`, `api_keys`, `agents`, `events`, `pending_approvals`, `breakglass_sessions`, `audit_log`.

Thread-safe with `threading.Lock`. Database schema managed via `migrations/` SQL files.

---

## Database Schema

```
tenants
  tenant_id (PK), name, slug (UNIQUE), contact_email, plan, created_at

api_keys
  key_id (PK), tenant_id (FK), name, role, key_hash, created_at,
  last_used_at, revoked_at

agents
  agent_id (PK), tenant_id (FK), name, owner, description,
  allowed_domains (JSON), created_at

events
  id (PK AUTOINCREMENT), tenant_id (FK), agent_id (FK),
  action, decision, anomaly, proof, findings (JSON),
  context (JSON), source_url, created_at

pending_approvals         ← new (0003)
  approval_id (PK), tenant_id, agent_id, action, context (JSON),
  actor, risk_score, created_at, status, decision,
  decided_by, decided_at

breakglass_sessions       ← new (0003)
  breakglass_id (PK), tenant_id, approved, created_at, expires_at,
  actor, reason, pin_hash, tenant_id, actions_overridden (JSON),
  status, used (0/1)

audit_log                 ← new (0003)
  id (PK AUTOINCREMENT), tenant_id, actor, action, decision,
  context (JSON), risk_score, breakglass_id, metadata (JSON),
  prev_hash, hash, timestamp
```

---

## Ports

| Service | Port | Note |
|---------|------|------|
| AI Guardian HTTP | 8000 (default) | Configurable via `PORT` env |

---

## File Locations (Container)

| Path | Contents |
|------|----------|
| `/app/ai_guardian/` | Application code |
| `/app/data/ai_guardian.db` | SQLite database |
| `/app/migrations/` | SQL migrations |
| `/app/scripts/run_migrations.py` | Migration runner |
