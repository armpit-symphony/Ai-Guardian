from __future__ import annotations

import logging
import time
import uuid
from collections import deque
from html import escape
from threading import Lock

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from .config import Settings, get_settings
from .models import AccessContext, AgentRegistration, MonitorRequest, TenantCreate
from .security import constant_time_contains
from .service import GuardianService


class RequestContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, service_name: str):
        super().__init__(app)
        self.logger = logging.getLogger("ai_guardian.request")
        self.service_name = service_name

    async def dispatch(self, request, call_next):
        request_id = request.headers.get("x-request-id", f"req_{uuid.uuid4().hex[:12]}")
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers["x-request-id"] = request_id
        self.logger.info(
            "request completed",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "service": self.service_name,
            },
        )
        return response


class InMemoryRateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit_per_minute = limit_per_minute
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def check(self, bucket: str) -> bool:
        now = time.time()
        with self._lock:
            values = self._events.setdefault(bucket, deque())
            while values and now - values[0] > 60:
                values.popleft()
            if len(values) >= self.limit_per_minute:
                return False
            values.append(now)
        return True


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or get_settings()
    app = FastAPI(
        title=app_settings.service_name,
        version="0.3.0",
        description="AI Guardian protects autonomous bots, products, and sites from unsafe actions and credential leaks.",
    )
    service = GuardianService(app_settings)
    limiter = InMemoryRateLimiter(app_settings.rate_limit_per_minute)
    app.add_middleware(RequestContextMiddleware, service_name=app_settings.service_name)

    def require_bootstrap_key(x_bootstrap_key: str = Header(...)) -> str:
        if not constant_time_contains(x_bootstrap_key, app_settings.bootstrap_api_keys):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bootstrap key.")
        return x_bootstrap_key

    def require_access(x_api_key: str = Header(...)) -> AccessContext:
        if not limiter.check(f"api:{x_api_key}"):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded.")
        access = service.authenticate(x_api_key)
        if not access:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid tenant API key.")
        return access

    def require_role(access: AccessContext, allowed: tuple[str, ...]) -> AccessContext:
        if access.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        return access

    @app.get("/health")
    def healthcheck() -> dict[str, str]:
        return {"status": "ok", "service": app_settings.service_name}

    @app.post("/api/v1/bootstrap/tenants", dependencies=[Depends(require_bootstrap_key)])
    def bootstrap_tenant(payload: TenantCreate):
        return service.bootstrap_tenant(payload)

    @app.get("/api/v1/tenants", dependencies=[Depends(require_bootstrap_key)])
    def list_tenants():
        return service.list_tenants()

    @app.post("/api/v1/agents")
    def register_agent(payload: AgentRegistration, access: AccessContext = Depends(require_access)):
        return service.register_agent(require_role(access, ("admin", "ingest")), payload)

    @app.get("/api/v1/agents")
    def list_agents(access: AccessContext = Depends(require_access)):
        return service.list_agents(access)

    @app.get("/api/v1/api-keys")
    def list_api_keys(access: AccessContext = Depends(require_access)):
        return service.list_api_keys(require_role(access, ("admin",)))

    @app.post("/api/v1/api-keys")
    def create_api_key(
        name: str = Query(..., min_length=2, max_length=80),
        role: str = Query(..., pattern="^(admin|ingest|viewer)$"),
        access: AccessContext = Depends(require_access),
    ):
        api_key, record = service.create_api_key(require_role(access, ("admin",)), name=name, role=role)
        return {"api_key": api_key, "key_meta": record}

    @app.post("/api/v1/api-keys/{key_id}/rotate")
    def rotate_api_key(
        key_id: str,
        replacement_name: str | None = Query(default=None, min_length=2, max_length=80),
        access: AccessContext = Depends(require_access),
    ):
        try:
            api_key, record = service.rotate_api_key(require_role(access, ("admin",)), key_id, replacement_name)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return {"api_key": api_key, "key_meta": record}

    @app.post("/api/v1/api-keys/{key_id}/revoke")
    def revoke_api_key(key_id: str, access: AccessContext = Depends(require_access)):
        record = service.revoke_api_key(require_role(access, ("admin",)), key_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found.")
        return record

    @app.post("/api/v1/monitor")
    def monitor_agent(payload: MonitorRequest, access: AccessContext = Depends(require_access)):
        try:
            return service.monitor(require_role(access, ("admin", "ingest")), payload)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    @app.get("/api/v1/events")
    def list_events(
        limit: int = Query(default=50, ge=1, le=200),
        decision: str | None = Query(default=None),
        access: AccessContext = Depends(require_access),
    ):
        return service.store.list_events(tenant_id=access.tenant_id, limit=limit, decision=decision)

    @app.get("/api/v1/alerts/summary")
    def alert_summary(access: AccessContext = Depends(require_access)):
        return service.store.alert_summary(access.tenant_id)

    @app.get("/api/v1/verify/{proof_hash}")
    def verify_proof(proof_hash: str, access: AccessContext = Depends(require_access)):
        return {"valid": service.verify_proof(access, proof_hash)}

    @app.get("/dashboard", dependencies=[Depends(require_bootstrap_key)])
    def dashboard() -> Response:
        return Response(content=_render_dashboard(service), media_type="text/html")

    return app


def _render_dashboard(service: GuardianService) -> str:
    cards = []
    for overview in service.tenant_overviews():
        top_finding = overview.alert_summary.top_findings[0]["code"] if overview.alert_summary.top_findings else "none"
        cards.append(
            f"""
            <article class="card">
              <h2>{escape(overview.tenant.name)}</h2>
              <p class="meta">{escape(overview.tenant.slug)} | {escape(overview.tenant.plan)}</p>
              <div class="grid">
                <div><strong>{overview.agent_count}</strong><span>Agents</span></div>
                <div><strong>{overview.alert_summary.total_events}</strong><span>Events</span></div>
                <div><strong>{overview.alert_summary.blocked_events}</strong><span>Blocked</span></div>
                <div><strong>{overview.alert_summary.review_events}</strong><span>Review</span></div>
              </div>
              <p class="finding">Top finding: {escape(top_finding)}</p>
            </article>
            """
        )
    body = "".join(cards) or '<article class="card empty"><h2>No tenants yet</h2><p>Bootstrap a tenant to start onboarding customers.</p></article>'
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>AI Guardian Dashboard</title>
        <style>
          :root {{
            --bg: #f5f1e8;
            --ink: #18231d;
            --accent: #0d6b4d;
            --panel: #fffaf1;
            --border: #d7c9ae;
          }}
          body {{ font-family: Georgia, 'Times New Roman', serif; background: radial-gradient(circle at top, #fff8e8, var(--bg)); color: var(--ink); margin: 0; }}
          main {{ max-width: 1100px; margin: 0 auto; padding: 48px 20px 80px; }}
          h1 {{ font-size: 3rem; margin-bottom: 0.25rem; }}
          .lead {{ max-width: 720px; font-size: 1.05rem; line-height: 1.6; }}
          .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; margin-top: 30px; }}
          .card {{ background: linear-gradient(180deg, #fffdf7, var(--panel)); border: 1px solid var(--border); border-radius: 20px; padding: 20px; box-shadow: 0 10px 30px rgba(24,35,29,0.08); }}
          .meta, .finding, span {{ color: #55645c; }}
          .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-top: 20px; }}
          strong {{ display: block; font-size: 1.8rem; color: var(--accent); }}
          .empty {{ text-align: center; padding: 40px 20px; }}
        </style>
      </head>
      <body>
        <main>
          <h1>AI Guardian Ops</h1>
          <p class="lead">Tenant-by-tenant visibility for the managed safety layer protecting bots, products, and production sites.</p>
          <section class="cards">{body}</section>
        </main>
      </body>
    </html>
    """


app = create_app()
