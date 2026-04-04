# AI Guardian

AI Guardian is a policy and monitoring layer for autonomous agents, internal automations, and production website workflows. It sits between an agent and the actions that matter, evaluates the request against safety rules, and returns a decision of `allow`, `review`, or `block`.

The product is built for teams shipping agents into real environments:
- founders protecting their own AI products
- agencies automating client websites
- operators who need audit trails before giving bots production access
- teams that want a control plane they can host and extend

## Why It Exists

Most agent stacks are good at doing work and weak at proving that the work was safe. AI Guardian fills that gap by giving you:
- tenant-scoped onboarding for customers or internal products
- scoped API keys for admin, ingestion, and read-only access
- policy evaluation before sensitive actions execute
- event history, proofs, and summaries for incident review
- webhook alerts when something needs attention

## Core Capabilities

- Tenant bootstrap with plan metadata
- Tenant-scoped API keys with rotation and revocation
- Agent registration with per-agent allowed domains
- Prompt-injection phrase detection
- Secret and token exposure detection
- Context checksum validation for tamper detection
- Blocklists and allowlists for risky domains
- Audit event history and proof verification
- CSV and JSON event export
- Lightweight operations dashboard
- SQLite for local development and PostgreSQL-ready production wiring

## Product Status

AI Guardian is in a strong deployable MVP state:
- local and container deployment are supported
- PostgreSQL migration scaffolding is included
- core monitoring and audit features are implemented
- tests cover the main service paths

The remaining work for a more complete commercial release is mostly around customer UX and infrastructure depth:
- gateway or Redis-backed rate limiting
- durable webhook retrying
- dashboard authentication and customer portal flows
- usage metering and billing

## Architecture At A Glance

1. An operator bootstraps a tenant.
2. AI Guardian issues the tenant's first admin API key.
3. Admins create ingest and viewer keys for bots and human operators.
4. Agents register themselves with per-agent domain constraints.
5. Every sensitive action is sent to `POST /api/v1/monitor`.
6. AI Guardian evaluates the request and stores an auditable event.
7. Teams review alerts, summaries, and exports through the API or dashboard.

## Quick Start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Set a bootstrap key:

```powershell
$env:AI_GUARDIAN_BOOTSTRAP_KEYS="replace-with-a-long-random-bootstrap-key"
```

3. Run the service:

```bash
uvicorn ai_guardian.main:app --reload
```

4. Open the API docs:

`http://127.0.0.1:8000/docs`

5. Run the local demo if you want a quick end-to-end example:

```bash
python -m demo.run_demo
```

## Docker Deployment

1. Copy [.env.example](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\.env.example) to `.env`
2. Set a real bootstrap key and optional PostgreSQL settings
3. Start the stack:

```bash
docker compose up --build -d
```

4. Open:
- API docs: `http://your-server:8000/docs`
- dashboard: `http://your-server:8000/dashboard`

The deployment files live in [Dockerfile](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\Dockerfile), [docker-compose.yml](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\docker-compose.yml), and [.env.example](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\.env.example).

## PostgreSQL Deployment

For production, prefer PostgreSQL over SQLite.

- Set `AI_GUARDIAN_DATABASE_URL`
- Run migrations:

```bash
python scripts/run_migrations.py
```

- Then start the app normally or through Docker

Migration SQL lives in [migrations](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\migrations), and the runner is [run_migrations.py](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\scripts\run_migrations.py).

## Environment Variables

- `AI_GUARDIAN_BOOTSTRAP_KEYS`: bootstrap keys used to create tenants
- `AI_GUARDIAN_DATABASE_URL`: PostgreSQL DSN for production
- `AI_GUARDIAN_DB_PATH`: SQLite path for local development
- `AI_GUARDIAN_WEBHOOK_URLS`: comma-separated webhook endpoints for alerts
- `AI_GUARDIAN_RATE_LIMIT_PER_MINUTE`: per-key in-memory rate limit
- `AI_GUARDIAN_BLOCKED_DOMAINS`: comma-separated blocked domains
- `AI_GUARDIAN_DEFAULT_ALLOWED_DOMAINS`: fallback allowed domains
- `AI_GUARDIAN_SUSPICIOUS_PHRASES`: phrases used for prompt-injection detection

## API Overview

Bootstrap and tenant setup:
- `POST /api/v1/bootstrap/tenants`
- `GET /api/v1/tenants`

Identity and access:
- `GET /api/v1/me`
- `GET /api/v1/api-keys`
- `POST /api/v1/api-keys`
- `POST /api/v1/api-keys/{key_id}/rotate`
- `POST /api/v1/api-keys/{key_id}/revoke`

Agent operations:
- `POST /api/v1/agents`
- `GET /api/v1/agents`

Monitoring and audit:
- `POST /api/v1/monitor`
- `GET /api/v1/events`
- `GET /api/v1/events/export`
- `GET /api/v1/alerts/summary`
- `GET /api/v1/verify/{proof_hash}`

Operations:
- `GET /health`
- `GET /dashboard`

## Example Workflow

Create a tenant:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/bootstrap/tenants" \
  -H "x-bootstrap-key: replace-with-a-long-random-bootstrap-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Armpit Symphony",
    "slug": "armpit-symphony",
    "contact_email": "ops@example.com",
    "plan": "growth"
  }'
```

Register an agent with the returned tenant API key:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/agents" \
  -H "x-api-key: tenant-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-bot",
    "owner": "armpit-symphony",
    "description": "Protects production workflows",
    "allowed_domains": ["github.com", "myproduct.com"]
  }'
```

Monitor a high-value action:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/monitor" \
  -H "x-api-key: tenant-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agt_example",
    "action": "Deploy homepage update",
    "context": {"environment": "production"},
    "source_url": "https://myproduct.com/admin",
    "context_checksum": "sha256-of-approved-context"
  }'
```

Export recent events:

```bash
curl "http://127.0.0.1:8000/api/v1/events/export?format=csv&limit=200" \
  -H "x-api-key: tenant-admin-key" \
  -o ai-guardian-events.csv
```

## Security Model

AI Guardian is designed to reduce risk before an agent reaches production actions. Current controls include:
- key-based tenant isolation
- per-role access control
- per-agent domain restrictions
- context tamper detection
- secret exposure detection
- risky-domain blocking
- review and block alerting
- audit proof verification

This should be treated as a security control layer, not as your only security boundary. For production, pair it with:
- HTTPS termination
- strong key management
- database backups
- external log shipping
- network restrictions
- gateway or Redis-backed rate limiting

## Repository Guide

- [main.py](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\ai_guardian\main.py): API routes and middleware
- [service.py](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\ai_guardian\service.py): service orchestration
- [policy.py](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\ai_guardian\policy.py): monitoring policy engine
- [storage.py](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\ai_guardian\storage.py): SQLite and PostgreSQL storage layer
- [notifications.py](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\ai_guardian\notifications.py): webhook dispatch
- [test_service.py](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\tests\test_service.py): service test coverage

## Roadmap

- dashboard authentication and customer-facing portal
- durable webhook retries
- Redis or gateway-backed rate limiting
- usage metering and billing
- language SDKs for customer agents
- signed attestations and stronger external audit storage

See [ARCHITECTURE.md](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\ARCHITECTURE.md) for the builder-oriented design notes.
