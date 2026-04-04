# Architecture and Builder's Guide

This version of AI Guardian is structured as a small SaaS control plane for protecting bots, automations, and web properties. The goal is to support both your own production workflows and future client tenants from the same backend foundation.

## Current Service Layout
- `ai_guardian/main.py`: FastAPI app factory, tenant bootstrap, scoped auth, and the HTML dashboard.
- `ai_guardian/service.py`: orchestration layer for tenants, API keys, agent onboarding, and monitoring decisions.
- `ai_guardian/policy.py`: policy engine for domain controls, prompt injection checks, secret detection, and tamper validation.
- `ai_guardian/storage.py`: SQLite-backed persistence for tenants, keys, agents, events, proofs, and summaries.
- `ai_guardian/security.py`: hashing, token detection, API-key hashing, and domain parsing helpers.
- `demo/run_demo.py`: local end-to-end SaaS-style simulation.
- `tests/test_service.py`: tests for tenant scoping, monitoring, and dashboard output.

## Core Flow
1. An operator bootstraps a tenant using a bootstrap key.
2. The service returns the first tenant admin key.
3. Admins create ingest or viewer keys for separate workloads.
4. Bots register agents under the tenant and send actions to `POST /api/v1/monitor`.
5. The policy engine evaluates:
   - memory checksum mismatches
   - suspicious instructions
   - blocked or unknown domains
   - leaked credentials or bearer tokens
   - high-impact actions that merit review
6. The service stores the event, generates a proof hash, and returns `allow`, `review`, or `block`.
7. Operators inspect summaries through API endpoints or `/dashboard`.

## Why This Is More Sellable
- Customer tenants now exist as first-class records.
- API keys are scoped by tenant and role.
- API keys can be rotated and revoked.
- Agents and events are isolated by tenant.
- There is a bootstrap path for onboarding a customer without touching code.
- There is a lightweight dashboard for operator visibility.
- Webhooks and request-level controls make the service more operationally usable.

## Suggested Packaging
- Starter: one tenant, basic policies, shared support.
- Growth: custom allowlists, more keys, webhook alerts, and onboarding support.
- Enterprise: SSO, stronger audit retention, custom deployment, and signed attestations.

## Security Priorities
- Replace shared bootstrap keys with a proper admin auth system or one-time setup flow.
- Move tenant data from SQLite to PostgreSQL before true multi-user production.
- Add request signing in addition to API keys.
- Replace the in-memory limiter with Redis or gateway-enforced rate limits.
- Add durable outbound notification retrying for blocked or tampered actions.

## Near-Term Build Path
1. Add webhook delivery for blocked and review events.
2. Add tenant branding and dashboard authentication.
3. Add usage metering and billing records.
4. Add SDKs so customer bots can call the API easily.
5. Add a PostgreSQL migration path.

## Deployment Notes
- Development: `uvicorn ai_guardian.main:app --reload`
- Demo bootstrap env var: `AI_GUARDIAN_BOOTSTRAP_KEYS`
- Hosted MVP: containerize with Gunicorn/Uvicorn workers behind HTTPS.
- Production data: use PostgreSQL, rotate keys, and back event logs with object storage.
