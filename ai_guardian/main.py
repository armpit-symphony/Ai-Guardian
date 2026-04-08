from __future__ import annotations

import logging
import time
import uuid
from collections import deque
from html import escape
from threading import Lock
import hashlib
import hmac

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

from .config import Settings, get_settings
from .models import (
    AccessContext,
    AgentRegistration,
    MonitorRequest,
    TenantCreate,
    BreakglassCreate,
    BreakglassResponse,
    AuditRecord,
    AuditVerifyResponse,
    GuardianDecisionResponse,
    PendingApprovalRecord,
    ApprovalDecideRequest,
)
from .security import constant_time_contains
from .service import GuardianService
from .breakglass import (
    create_session,
    validate_session,
    use_session,
    revoke_session,
    get_session,
    list_active_sessions,
)
from .audit import audit_log
from .enforcement import (
    get_pending,
    get_pending_for_tenant,
    approve_pending,
    deny_pending,
)
from .interceptor import guardian, can_approve, resolve_pending_execution
from .config import settings as app_settings


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
        version="0.4.0",
        description="AI Guardian protects autonomous bots, products, and sites from unsafe actions and credential leaks.",
    )
    service = GuardianService(app_settings)
    limiter = InMemoryRateLimiter(app_settings.rate_limit_per_minute)
    app.add_middleware(RequestContextMiddleware, service_name=app_settings.service_name)

    def require_bootstrap_key(x_bootstrap_key: str = Header(...)) -> str:
        if not constant_time_contains(x_bootstrap_key, app_settings.bootstrap_api_keys):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bootstrap key.")
        return x_bootstrap_key

    def require_dashboard_access(request: Request) -> bool:
        if not app_settings.dashboard_password:
            return True
        cookie = request.cookies.get("ai_guardian_dashboard")
        if not cookie or not _validate_dashboard_session(cookie, app_settings.dashboard_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Dashboard login required.")
        return True

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

    @app.get("/api/v1/me")
    def get_me(access: AccessContext = Depends(require_access)):
        try:
            return service.access_profile(access)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

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

    @app.post("/api/v1/monitor", response_model=GuardianDecisionResponse, tags=["Guardian"])
    def monitor_agent(payload: MonitorRequest, access: AccessContext = Depends(require_access)):
        """
        Central guardian interceptor — ALL actions flow through this endpoint.
        Returns standard GuardianDecision contract:
        {
            "decision": "allowed | blocked | pending_approval",
            "reason": "...",
            "risk_score": 0-100,
            "requires_approval": bool,
            "breakglass_used": bool,
            "approval_id": str | None,
            "proof": str | None
        }
        """
        decision = guardian.evaluate(access, payload)
        return GuardianDecisionResponse(
            decision=decision.decision,
            reason=decision.reason,
            risk_score=decision.risk_score,
            requires_approval=decision.requires_approval,
            breakglass_used=decision.breakglass_used,
            approval_id=decision.approval_id,
            proof=decision.proof,
        )

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

    @app.get("/api/v1/events/export")
    def export_events(
        format: str = Query(default="csv", pattern="^(csv|json)$"),
        limit: int = Query(default=500, ge=1, le=5000),
        decision: str | None = Query(default=None),
        access: AccessContext = Depends(require_access),
    ):
        scoped_access = require_role(access, ("admin", "viewer"))
        if format == "json":
            return service.store.list_events(tenant_id=scoped_access.tenant_id, limit=limit, decision=decision)
        csv_body = service.export_events_csv(scoped_access, decision=decision, limit=limit)
        return Response(
            content=csv_body,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="ai-guardian-events.csv"'},
        )

    @app.get("/api/v1/verify/{proof_hash}")
    def verify_proof(proof_hash: str, access: AccessContext = Depends(require_access)):
        return {"valid": service.verify_proof(access, proof_hash)}

    # ─── Breakglass Endpoints ───

    @app.post("/api/v1/breakglass", response_model=BreakglassResponse, tags=["Guardian"])
    def create_breakglass(
        payload: BreakglassCreate,
        access: AccessContext = Depends(require_access),
    ):
        """
        Create a breakglass session for emergency override.
        Requires PIN + business justification (min 10 chars).
        Default expiry: 15 minutes.
        """
        if access.role not in ("admin",):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required for breakglass.")

        session = create_session(
            tenant_id=access.tenant_id,
            actor=access.key_id,
            reason=payload.reason,
            pin=payload.pin,
            duration_minutes=payload.duration_minutes,
        )
        if not session:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid PIN or reason too short (min 10 chars).")

        audit_log.append(
            tenant_id=access.tenant_id,
            actor=access.key_id,
            action="breakglass_create",
            decision="breakglass_used",
            context={"reason": payload.reason},
            risk_score=100,
            breakglass_id=session.breakglass_id,
        )

        return BreakglassResponse(
            breakglass_id=session.breakglass_id,
            approved=session.approved,
            expires_at=session.expires_at,
            actor=session.actor,
        )

    @app.post("/api/v1/breakglass/{breakglass_id}/revoke", tags=["Guardian"])
    def revoke_breakglass(
        breakglass_id: str,
        access: AccessContext = Depends(require_access),
    ):
        """Revoke an active breakglass session."""
        if access.role not in ("admin",):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")

        session = get_session(breakglass_id)
        if not session or session.tenant_id != access.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Breakglass session not found.")

        success = revoke_session(breakglass_id)
        if success:
            audit_log.append(
                tenant_id=access.tenant_id,
                actor=access.key_id,
                action="breakglass_revoke",
                decision="breakglass_used",
                context={"breakglass_id": breakglass_id},
                risk_score=100,
                breakglass_id=breakglass_id,
            )
        return {"status": "revoked" if success else "failed", "breakglass_id": breakglass_id}

    @app.get("/api/v1/breakglass", tags=["Guardian"])
    def list_breakglass_sessions(access: AccessContext = Depends(require_access)):
        """List all active breakglass sessions for the tenant."""
        if access.role not in ("admin",):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")
        sessions = list_active_sessions(access.tenant_id)
        return [session._asdict() for session in sessions]

    @app.post("/api/v1/breakglass/{breakglass_id}/use", tags=["Guardian"])
    def use_breakglass_session(
        breakglass_id: str,
        action: str,
        access: AccessContext = Depends(require_access),
    ):
        """
        Use an active breakglass session to override for a specific action.
        Records the use in the immutable audit log.
        """
        session = get_session(breakglass_id)
        if not session or session.tenant_id != access.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Breakglass session not found.")

        is_valid, reason = validate_session(breakglass_id)
        if not is_valid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

        success = use_session(breakglass_id, action)
        audit_log.append(
            tenant_id=access.tenant_id,
            actor=access.key_id,
            action=f"breakglass_override:{action}",
            decision="breakglass_used",
            context={"breakglass_id": breakglass_id, "action": action},
            risk_score=100,
            breakglass_id=breakglass_id,
        )

        return {"status": "used" if success else "failed", "breakglass_id": breakglass_id, "action": action}

    # ─── Approval Queue Endpoints ───

    @app.get("/api/v1/approvals", response_model=list[PendingApprovalRecord], tags=["Guardian"])
    def list_pending_approvals(access: AccessContext = Depends(require_access)):
        """List all pending approvals for the tenant."""
        pending = get_pending_for_tenant(access.tenant_id)
        return [PendingApprovalRecord(
            approval_id=r.approval_id,
            tenant_id=r.tenant_id,
            agent_id=r.agent_id,
            action=r.action,
            context=r.context,
            actor=r.actor,
            risk_score=r.risk_score,
            created_at=r.created_at,
            status=r.status,
            decision=r.decision,
            decided_by=r.decided_by,
            decided_at=r.decided_at,
        ) for r in pending]

    @app.get("/api/v1/approvals/{approval_id}", response_model=PendingApprovalRecord, tags=["Guardian"])
    def get_approval(approval_id: str, access: AccessContext = Depends(require_access)):
        """Get a specific approval by ID."""
        pending = get_pending(approval_id)
        if not pending:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
        if pending.tenant_id != access.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant isolation violation")
        return PendingApprovalRecord(
            approval_id=pending.approval_id,
            tenant_id=pending.tenant_id,
            agent_id=pending.agent_id,
            action=pending.action,
            context=pending.context,
            actor=pending.actor,
            risk_score=pending.risk_score,
            created_at=pending.created_at,
            status=pending.status,
            decision=pending.decision,
            decided_by=pending.decided_by,
            decided_at=pending.decided_at,
        )

    @app.post("/api/v1/approvals/{approval_id}/decide", response_model=PendingApprovalRecord, tags=["Guardian"])
    def decide_approval(
        approval_id: str,
        action: ApprovalDecideRequest,
        access: AccessContext = Depends(require_access),
    ):
        """
        Approve or deny a pending approval.
        Only admin/operator can decide.
        """
        if not can_approve(access):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to decide approvals")

        pending = get_pending(approval_id)
        if not pending:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
        if pending.tenant_id != access.tenant_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant isolation violation")
        if pending.status != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Approval is {pending.status}, cannot decide")

        if action.decision == "approve":
            updated = approve_pending(approval_id, access.key_id)
        else:
            updated = deny_pending(approval_id, access.key_id)

        audit_log.append(
            tenant_id=access.tenant_id,
            actor=access.key_id,
            action=f"guardian_approval_{action.decision}d:{pending.action}",
            decision=action.decision,
            context={
                "approval_id": approval_id,
                "agent_id": pending.agent_id,
                "action": pending.action,
                "actor": pending.actor,
            },
            risk_score=pending.risk_score,
        )

        return PendingApprovalRecord(
            approval_id=updated.approval_id,
            tenant_id=updated.tenant_id,
            agent_id=updated.agent_id,
            action=updated.action,
            context=updated.context,
            actor=updated.actor,
            risk_score=updated.risk_score,
            created_at=updated.created_at,
            status=updated.status,
            decision=updated.decision,
            decided_by=updated.decided_by,
            decided_at=updated.decided_at,
        )

    # ─── Audit Log Endpoints ───

    @app.get("/api/v1/audit/logs", response_model=list[AuditRecord], tags=["Audit"])
    def get_audit_logs(
        limit: int = Query(default=100, ge=1, le=1000),
        access: AccessContext = Depends(require_access),
    ):
        """Get governance audit log entries (breakglass, overrides, admin actions)."""
        if access.role not in ("admin", "viewer"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        entries = audit_log.get_recent(access.tenant_id, limit)
        return entries

    @app.get("/api/v1/audit/verify", response_model=AuditVerifyResponse, tags=["Audit"])
    def verify_audit_integrity(access: AccessContext = Depends(require_access)):
        """Verify hash-chain integrity of the governance audit log."""
        if access.role not in ("admin",):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")
        valid, errors = audit_log.verify_integrity(access.tenant_id)
        return AuditVerifyResponse(
            valid=valid,
            total_entries=audit_log.count(access.tenant_id),
            errors=errors,
        )

    @app.get("/api/v1/audit/export", tags=["Audit"])
    def export_audit_log(
        format: str = Query(default="json", pattern="^(json|csv)$"),
        limit: int = Query(default=500, ge=1, le=5000),
        access: AccessContext = Depends(require_access),
    ):
        """Export governance audit log as JSON or CSV."""
        if access.role not in ("admin", "viewer"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        entries = audit_log.get_recent(access.tenant_id, limit)

        if format == "json":
            return entries

        # CSV export
        if not entries:
            return Response(content="", media_type="text/csv")
        header = "id,timestamp,actor,action,decision,context,risk_score,breakglass_id,hash,prev_hash\n"
        rows = []
        for e in entries:
            rows.append(
                f"{e['id']},{e['timestamp']},{e['actor']},{e['action']},{e['decision']},"
                f'"{str(e.get("context", {}))}"'
            )
        body = header + "\n".join(rows)
        return Response(
            content=body,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="ai-guardian-audit-log.csv"'},
        )

    @app.get("/dashboard/login")
    def dashboard_login_page(error: str | None = Query(default=None)) -> Response:
        return Response(content=_render_dashboard_login(error=error), media_type="text/html")

    @app.post("/dashboard/login")
    def dashboard_login(password: str = Form(...)):
        if not app_settings.dashboard_password:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        if not hmac.compare_digest(password, app_settings.dashboard_password):
            return RedirectResponse(url="/dashboard/login?error=invalid", status_code=status.HTTP_303_SEE_OTHER)
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="ai_guardian_dashboard",
            value=_sign_dashboard_session(app_settings.dashboard_password),
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 8,
        )
        return response

    @app.post("/dashboard/logout")
    def dashboard_logout():
        response = RedirectResponse(url="/dashboard/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie("ai_guardian_dashboard")
        return response

    @app.post("/dashboard/bootstrap")
    def dashboard_bootstrap_tenant(
        request: Request,
        name: str = Form(...),
        slug: str = Form(...),
        contact_email: str = Form(...),
        plan: str = Form(...),
        _: bool = Depends(require_dashboard_access),
    ):
        bootstrap_key = request.headers.get("x-bootstrap-key")
        if not app_settings.dashboard_password and not bootstrap_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap key required when dashboard password is not configured.")
        if not app_settings.dashboard_password:
            require_bootstrap_key(bootstrap_key)  # type: ignore[arg-type]
        service.bootstrap_tenant(
            TenantCreate(name=name, slug=slug, contact_email=contact_email, plan=plan)  # type: ignore[arg-type]
        )
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/dashboard")
    def dashboard(request: Request) -> Response:
        if app_settings.dashboard_password:
            require_dashboard_access(request)
        elif "x-bootstrap-key" in request.headers:
            require_bootstrap_key(request.headers["x-bootstrap-key"])
        else:
            return RedirectResponse(url="/dashboard/login", status_code=status.HTTP_303_SEE_OTHER)
        return Response(content=_render_dashboard(service, password_enabled=bool(app_settings.dashboard_password)), media_type="text/html")

    return app


def _render_dashboard(service: GuardianService, password_enabled: bool = False) -> str:
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
    auth_block = (
        """
        <form method="post" action="/dashboard/logout" class="logout">
          <button type="submit">Log out</button>
        </form>
        """
        if password_enabled
        else ""
    )
    onboarding = """
      <section class="panel">
        <h2>Bootstrap Tenant</h2>
        <form method="post" action="/dashboard/bootstrap" class="form-grid">
          <input name="name" placeholder="Tenant name" required />
          <input name="slug" placeholder="tenant-slug" pattern="[a-z0-9-]+" required />
          <input name="contact_email" placeholder="ops@example.com" type="email" required />
          <select name="plan">
            <option value="starter">starter</option>
            <option value="growth" selected>growth</option>
            <option value="enterprise">enterprise</option>
          </select>
          <button type="submit">Create tenant</button>
        </form>
      </section>
    """
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
          .panel {{ margin-top: 24px; background: linear-gradient(180deg, #fffdf7, var(--panel)); border: 1px solid var(--border); border-radius: 20px; padding: 20px; box-shadow: 0 10px 30px rgba(24,35,29,0.08); }}
          .meta, .finding, span {{ color: #55645c; }}
          .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-top: 20px; }}
          .form-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 16px; }}
          input, select, button {{ font: inherit; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border); }}
          button {{ background: var(--accent); color: white; cursor: pointer; }}
          .logout {{ display: flex; justify-content: flex-end; margin-top: 12px; }}
          strong {{ display: block; font-size: 1.8rem; color: var(--accent); }}
          .empty {{ text-align: center; padding: 40px 20px; }}
        </style>
      </head>
      <body>
        <main>
          <h1>AI Guardian Ops</h1>
          <p class="lead">Tenant-by-tenant visibility for the managed safety layer protecting bots, products, and production sites.</p>
          {auth_block}
          {onboarding}
          <section class="cards">{body}</section>
        </main>
      </body>
    </html>
    """


def _render_dashboard_login(error: str | None = None) -> str:
    error_html = '<p class="error">Invalid password. Try again.</p>' if error == "invalid" else ""
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>AI Guardian Login</title>
        <style>
          body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: linear-gradient(145deg, #f4ead6, #fffef9); font-family: Georgia, 'Times New Roman', serif; color: #1d2b23; }}
          .card {{ width: min(420px, calc(100vw - 32px)); background: rgba(255,250,241,0.95); border: 1px solid #d7c9ae; border-radius: 24px; padding: 28px; box-shadow: 0 12px 40px rgba(24,35,29,0.12); }}
          h1 {{ margin-top: 0; }}
          p {{ color: #55645c; line-height: 1.5; }}
          input, button {{ width: 100%; font: inherit; padding: 12px 14px; border-radius: 12px; border: 1px solid #d7c9ae; margin-top: 12px; }}
          button {{ background: #0d6b4d; color: white; cursor: pointer; }}
          .error {{ color: #9b2c2c; }}
        </style>
      </head>
      <body>
        <main class="card">
          <h1>AI Guardian Dashboard</h1>
          <p>Sign in with the dashboard password to manage tenants and review product activity.</p>
          {error_html}
          <form method="post" action="/dashboard/login">
            <input type="password" name="password" placeholder="Dashboard password" required />
            <button type="submit">Sign in</button>
          </form>
        </main>
      </body>
    </html>
    """


def _sign_dashboard_session(password: str) -> str:
    return hashlib.sha256(f"ai-guardian:{password}".encode("utf-8")).hexdigest()


def _validate_dashboard_session(cookie: str, password: str) -> bool:
    expected = _sign_dashboard_session(password)
    return hmac.compare_digest(cookie, expected)


app = create_app()
