# AI Guardian — Overview

AI Guardian is a production-ready governance layer for autonomous AI agents. It enforces security policies, manages approval workflows, provides tamper-evident audit logs, and supports emergency breakglass overrides.

---

## What It Does

| Capability | Description |
|---|---|
| **Policy enforcement** | Blocks critical actions (delete_all_files, exec_code, etc.), requires approval for high-risk actions |
| **Approval queue** | Risky actions enter a pending queue; admins approve or deny |
| **SSRF protection** | Blocks requests to internal/private addresses (localhost, 169.254.169.254, etc.) |
| **Breakglass** | Emergency override sessions for operational emergencies (PIN-gated, one-time use) |
| **Audit log** | Immutable, hash-chained audit trail for all governance events |
| **Multi-tenant** | Full tenant isolation; each tenant has independent keys, agents, and audit logs |

---

## Architecture at a Glance

```
Request → FastAPI → GuardianInterceptor.evaluate()
                              ├── Step 0: Critical blocklist
                              ├── Step 1: RBAC (role check)
                              ├── Step 2: Breakglass override
                              ├── Step 3: Policy + risk scoring
                              └── Step 4: Decision
                                         ├── allowed     → execute
                                         ├── blocked     → reject
                                         └── pending     → approval queue
```

---

## Roles

| Role | Can Submit | Can Approve/Deny | Can View Audit | Can Manage Keys |
|------|-----------|-----------------|----------------|----------------|
| **admin** | ✅ | ✅ | ✅ | ✅ |
| **ingest** | ✅ | ❌ | ❌ | ❌ |
| **viewer** | ❌ | ❌ | ✅ | ❌ |

---

## Verified Status

| Component | Status |
|-----------|--------|
| SQLite persistence | ✅ Verified (restarts safe) |
| PostgreSQL | ⚠️ Supported target — methods implemented, not end-to-end tested |
| Docker | ✅ Verified |
| CI (GitHub Actions) | ✅ Running |
| Phase 7 test suite | ✅ 74/74 passing |

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/armpit-symphony/Ai-Guardian.git
cd Ai-Guardian
pip install -e .

# 2. Configure environment
cp .env.example .env
# Edit .env — set AI_GUARDIAN_BOOTSTRAP_KEYS to a long random string

# 3. Run
python -m ai_guardian.main
# Or with Docker:
docker compose up --build

# 4. Verify
curl http://localhost:8000/health
```

---

## Repository Structure

```
ai_guardian/
├── main.py          # FastAPI app, all HTTP endpoints
├── models.py        # Request/response Pydantic schemas
├── interceptor.py    # GuardianInterceptor — central evaluation pipeline
├── enforcement.py   # Approval queue (pending_approvals → SQLite)
├── breakglass.py    # Emergency override sessions (breakglass_sessions → SQLite)
├── audit.py         # Immutable audit log (audit_log → SQLite)
├── storage.py       # SQLite + PostgresStore CRUD
├── config.py        # Environment configuration
└── service.py       # Business logic layer
migrations/
├── 0001_initial.sql
├── 0002_api_key_revocation.sql
└── 0003_persistence.sql   # approvals, breakglass, audit tables
docs/
├── QUICKSTART.md
├── DEPLOYMENT.md
├── ARCHITECTURE.md
├── SECURITY_MODEL.md
├── API.md
├── OPERATIONS.md
├── BREAKGLASS_RUNBOOK.md
└── AUDIT_TAXONOMY.md
tests/               # Phase 7 pytest suite (74 tests)
.github/workflows/ci.yml
Dockerfile
docker-compose.yml
```

---

## Documentation

- [Quick Start](docs/QUICKSTART.md) — First-time setup, bootstrap, first API call
- [Deployment](docs/DEPLOYMENT.md) — Docker, compose, production configuration
- [Architecture](docs/ARCHITECTURE.md) — Component diagram, data flow
- [Security Model](docs/SECURITY_MODEL.md) — Threat model, SSRF, RBAC, breakglass
- [API Reference](docs/API.md) — All endpoints, request/response schemas
- [Operations](docs/OPERATIONS.md) — Monitoring, restart procedures, backups
- [Breakglass Runbook](docs/BREAKGLASS_RUNBOOK.md) — Emergency override procedure
- [Audit Taxonomy](docs/AUDIT_TAXONOMY.md) — Audit event types, hash chain verification

---

## Version

Current: **0.4.0** (`feature/breakglass-hashchain` branch)
