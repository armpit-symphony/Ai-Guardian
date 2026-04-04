# AI Guardian

AI Guardian is a managed safety layer for autonomous agents, internal bots, and production website automations. It sits between your bot runtime and sensitive actions, then decides whether to allow, review, or block each action based on policy.

This version is shaped for a service business:
- Bootstrap a customer tenant.
- Issue scoped API keys for that tenant.
- Register protected agents under that tenant.
- Monitor actions and expose tenant-specific risk summaries.

## What It Does
- Creates customer tenants with plan metadata.
- Issues tenant-scoped API keys with `admin`, `ingest`, and `viewer` roles.
- Supports API-key rotation and revocation.
- Registers protected agents with per-agent domain allowlists.
- Monitors actions, source URLs, and memory snapshots.
- Detects prompt injection phrases, secret leaks, blocked domains, and context tampering.
- Persists audit events and risk summaries.
- Sends webhook alerts for `review` and `block` decisions.
- Adds request IDs and basic per-key rate limiting at the API boundary.
- Serves a lightweight operations dashboard at `/dashboard`.

## Quick Start
1. Install dependencies: `pip install -r requirements.txt`
2. Set a bootstrap key: PowerShell example `$env:AI_GUARDIAN_BOOTSTRAP_KEYS="replace-with-a-real-bootstrap-key"`
3. Optional alerts: `$env:AI_GUARDIAN_WEBHOOK_URLS="https://your-alert-endpoint.example/hook"`
4. Optional rate limit override: `$env:AI_GUARDIAN_RATE_LIMIT_PER_MINUTE="120"`
5. Run the API: `uvicorn ai_guardian.main:app --reload`
6. Run the demo: `python -m demo.run_demo`
7. Open docs: `http://127.0.0.1:8000/docs`

## Docker Deploy
1. Copy [.env.example](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\.env.example) to `.env` and set a real bootstrap key.
2. Build and start: `docker compose up --build -d`
3. Open the API at `http://your-server:8000/docs`
4. Persisted SQLite data is stored in the `ai_guardian_data` Docker volume.

The container entrypoint is defined in [Dockerfile](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\Dockerfile), and the server bundle is in [docker-compose.yml](C:\Users\yopsp\OneDrive\Documents\Playground\Ai-Guardian\docker-compose.yml).

## PostgreSQL Mode
- Set `AI_GUARDIAN_DATABASE_URL` to a Postgres DSN such as `postgresql://ai_guardian:change-me@postgres:5432/ai_guardian`.
- Run migrations with `python scripts/run_migrations.py`.
- The app still supports SQLite for local development, but Postgres is now the preferred production path.

## Tenant Bootstrap Flow
1. `POST /api/v1/bootstrap/tenants` with header `x-bootstrap-key`.
2. Save the returned tenant admin API key.
3. Use that tenant key in `x-api-key` for normal agent and monitoring endpoints.
4. Create additional scoped keys for CI, workers, dashboards, or customer staff.

## Main Endpoints
- `POST /api/v1/bootstrap/tenants` creates a tenant and returns its first admin API key.
- `GET /api/v1/tenants` lists tenants with the bootstrap key.
- `POST /api/v1/api-keys` issues a new scoped tenant API key.
- `POST /api/v1/api-keys/{key_id}/rotate` rotates a tenant key and returns the replacement secret once.
- `POST /api/v1/api-keys/{key_id}/revoke` revokes a tenant key.
- `GET /api/v1/api-keys` lists tenant keys.
- `POST /api/v1/agents` creates a protected agent profile.
- `GET /api/v1/agents` lists tenant agents.
- `POST /api/v1/monitor` evaluates an action and returns a decision plus proof.
- `GET /api/v1/events` shows tenant audit events.
- `GET /api/v1/alerts/summary` shows tenant risk totals.
- `GET /api/v1/verify/{proof_hash}` confirms a proof exists inside that tenant.
- `GET /dashboard` shows a simple operator overview across tenants.

## Service Fit
- Protect your own bots, site workflows, and operator dashboards first.
- Offer tenant onboarding and monitoring to clients as a managed control plane.
- Use scoped keys to separate ingestion, admin, and read-only viewing.

## Hardening Priorities For Your Own Products
- Put AI Guardian in front of any bot that can publish, deploy, edit content, or touch credentials.
- Give each bot its own tenant or at least its own scoped ingest key if you want tighter blast-radius control.
- Restrict each agent to its own approved domains instead of using a broad global allowlist.
- Require checksum validation for high-risk memory or prompt state passed between tools.
- Feed blocked events into a human-review queue before any production action is retried.

## Next Commercial Steps
- Add webhooks, Slack, or email alerting.
- Add signed attestations and immutable storage.
- Add SDKs for Python, Node, and browser workers.
- Add billing, usage metering, and a full customer portal.

See `ARCHITECTURE.md` for the service design and roadmap.
