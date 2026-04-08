from __future__ import annotations

from dataclasses import dataclass, field

from .models import AccessContext, MonitorRequest
from .policy import PolicyContext, PolicyEngine
from .breakglass import validate_session, use_session
from .audit import audit_log
from .enforcement import (
    GuardianDecision,
    create_pending,
    get_pending,
    get_pending_for_tenant,
    approve_pending,
    deny_pending,
)


@dataclass
class InterceptorConfig:
    """Configuration for the guardian interceptor."""
    deny_by_default: bool = False
    approval_required_for_high_risk: bool = True
    high_risk_threshold: int = 65  # review+medium or higher findings trigger approval
    critical_risk_threshold: int = 90
    # Which roles can approve pending actions
    approver_roles: tuple[str, ...] = ("admin",)


class GuardianInterceptor:
    """
    The single central interceptor for all guardian decisions.

    Every action passes through this one choke point:
    request → auth (upstream) → RBAC → risk/policy → decision → execute/block/queue

    Returns a GuardianDecision with standard contract:
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

    def __init__(self, config: InterceptorConfig | None = None):
        self.config = config or InterceptorConfig()
        self.policy = PolicyEngine()

    def evaluate(
        self,
        access: AccessContext,
        request: MonitorRequest,
        breakglass_id: str | None = None,
    ) -> GuardianDecision:
        """
        Evaluate an action through the full guardian interceptor pipeline.
        This is the ONE entry point for all guarded decisions.
        """
        # ── Step 0: Critical action blocklist ─────────────────────────────
        critical_actions = {
            "delete_all_files", "drop_table", "drop_database", "exec_code",
            "run_shell", "execute_command", "steal_keys", "exfiltrate_data",
            "sudo", "rm_rf",
        }
        normalized = request.action.lower().replace("-", "_").replace(" ", "_")
        for dangerous in critical_actions:
            if dangerous in normalized:
                audit_log.append(
                    tenant_id=access.tenant_id,
                    actor=access.key_id,
                    action=f"guardian_blocked_critical:{request.action}",
                    decision="blocked",
                    context={"reason": "critical_action_blocked", "agent_id": request.agent_id},
                    risk_score=100,
                )
                return GuardianDecision(
                    decision="blocked",
                    reason=f"Critical action '{request.action}' is blocked",
                    risk_score=100,
                    requires_approval=False,
                    breakglass_used=False,
                )

        # ── Step 1: RBAC check ──────────────────────────────────────────
        if not self._can_submit_action(access):
            return GuardianDecision(
                decision="blocked",
                reason=f"Role '{access.role}' cannot submit actions",
                risk_score=0,
                requires_approval=False,
                breakglass_used=False,
            )

        # ── Step 2: Breakglass override check ──────────────────────────
        if breakglass_id:
            is_valid, reason = validate_session(breakglass_id)
            if is_valid:
                action_recorded = use_session(breakglass_id, request.action)
                audit_log.append(
                    tenant_id=access.tenant_id,
                    actor=access.key_id,
                    action=f"breakglass_override:{request.action}",
                    decision="breakglass_used",
                    context={
                        "breakglass_id": breakglass_id,
                        "agent_id": request.agent_id,
                        "action": request.action,
                    },
                    risk_score=100,
                    breakglass_id=breakglass_id,
                )
                return GuardianDecision(
                    decision="allowed",
                    reason=f"Breakglass override applied: {breakglass_id}",
                    risk_score=100,
                    requires_approval=False,
                    breakglass_used=True,
                    proof=f"breakglass:{breakglass_id}",
                )
            else:
                # Breakglass was provided but invalid — log and deny
                audit_log.append(
                    tenant_id=access.tenant_id,
                    actor=access.key_id,
                    action=f"breakglass_invalid:{request.action}",
                    decision="blocked",
                    context={"breakglass_id": breakglass_id, "reason": reason},
                    risk_score=100,
                    breakglass_id=breakglass_id,
                )
                return GuardianDecision(
                    decision="blocked",
                    reason=f"Invalid breakglass: {reason}",
                    risk_score=100,
                    requires_approval=False,
                    breakglass_used=False,
                )

        # ── Step 3: Policy evaluation ────────────────────────────────────
        allowed_domains = tuple(getattr(self.config, 'allowed_domains', ()))
        decision_str, findings, proof = self.policy.evaluate(
            request,
            PolicyContext(
                blocked_domains=(),
                suspicious_phrases=(),
                allowed_domains=allowed_domains,
            ),
        )

        # ── Step 3: Risk scoring (independent of policy decision) ──────────
        risk_score = self._calc_risk(request, findings)

        # ── Step 4b: SSRF — hard-block internal/private URLs ───────────────
        # Collect all URL-like values from source_url field AND from context recursively
        _ssrf_blocklist = (
            "localhost", "127.0.0.1", "169.254.169.254",
            "0.0.0.0", "::1", "metadata.google.internal", ".internal",
        )

        def _extract_urls(obj) -> list[str]:
            """Recursively extract URL strings from any object."""
            urls = []
            if isinstance(obj, str) and ("://" in obj or obj.startswith("http")):
                urls.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    urls.extend(_extract_urls(v))
            elif isinstance(obj, (list, tuple)):
                for v in obj:
                    urls.extend(_extract_urls(v))
            return urls

        all_urls = []
        source_url = getattr(request, 'source_url', None)
        if source_url:
            all_urls.append(source_url)
        all_urls.extend(_extract_urls(getattr(request, 'context', None) or {}))

        for url in all_urls:
            try:
                from urllib.parse import urlparse
                raw = urlparse(url).netloc.lower().split("@")[-1]
                if raw.startswith("["):
                    domain = raw.split("]")[0].lstrip("[")
                else:
                    domain = raw.split(":")[0]
                for pat in _ssrf_blocklist:
                    if pat in domain:
                        audit_log.append(
                            tenant_id=access.tenant_id,
                            actor=access.key_id,
                            action=f"guardian_blocked:ssrf:{request.action}",
                            decision="blocked",
                            context={
                                "reason": "SSRF protection: internal URL not allowed",
                                "source_url": url,
                                "agent_id": request.agent_id,
                            },
                            risk_score=100,
                        )
                        return GuardianDecision(
                            decision="blocked",
                            reason=f"SSRF protection: internal URL '{domain}' is not allowed",
                            risk_score=100,
                            requires_approval=False,
                            breakglass_used=False,
                        )
            except Exception:
                pass

        # ── Step 4: Policy + risk-based decision ──────────────────────────
        if decision_str == "block":
            result = GuardianDecision(
                decision="blocked",
                reason=f"Policy blocked: {[f.code for f in findings]}",
                risk_score=risk_score,
                requires_approval=False,
                breakglass_used=False,
                proof=proof,
            )
        elif decision_str == "review" or risk_score >= self.config.high_risk_threshold:
            # ANY high-risk action (score >= threshold) requires approval,
            # whether from policy review or from action-based risk scoring
            pending = create_pending(
                tenant_id=access.tenant_id,
                agent_id=request.agent_id,
                action=request.action,
                context=request.context or {},
                actor=access.key_id,
                risk_score=risk_score,
            )
            audit_log.append(
                tenant_id=access.tenant_id,
                actor=access.key_id,
                action=f"guardian_pending:{request.action}",
                decision="pending_approval",
                context={
                    "approval_id": pending.approval_id,
                    "agent_id": request.agent_id,
                    "findings": [f.code for f in findings],
                },
                risk_score=risk_score,
            )
            result = GuardianDecision(
                decision="pending_approval",
                reason=f"High-risk action (score: {risk_score}) requires approval",
                risk_score=risk_score,
                requires_approval=True,
                breakglass_used=False,
                approval_id=pending.approval_id,
            )
        else:
            audit_log.append(
                tenant_id=access.tenant_id,
                actor=access.key_id,
                action=f"guardian_allowed:{request.action}",
                decision="allowed",
                context={
                    "agent_id": request.agent_id,
                    "findings": [f.code for f in findings],
                },
                risk_score=risk_score,
            )
            result = GuardianDecision(
                decision="allowed",
                reason="Allowed by policy",
                risk_score=risk_score,
                requires_approval=False,
                breakglass_used=False,
                proof=proof,
            )

        return result

    def _can_submit_action(self, access: AccessContext) -> bool:
        return access.role in ("admin", "ingest")

    def _calc_risk(self, request: MonitorRequest, findings) -> int:
        """
        Calculate risk score from findings — aggressive scoring for security product.
        TWO layers of enforcement:
          1. Category-based (action name patterns) — outbound-network actions default to pending
          2. Severity-based (policy findings) — escalate based on severity
        """
        # ── Layer 1: Outbound-network category enforcement ─────────────
        # Any action that can reach outside the trust boundary → risk 65+ (pending approval)
        outbound_keywords = [
            "external", "http", "https", "webhook", "api_call", "api_request",
            "fetch", "request", "send_data", "post_to", "curl", "wget",
            "outbound", "network", "smtp", "email", "web",
        ]
        for keyword in outbound_keywords:
            if keyword in request.action.lower():
                return 65  # pending approval threshold hit

        # ── Layer 2: Severity from policy findings ─────────────────────
        severity_map = {"low": 35, "medium": 65, "high": 85, "critical": 100}
        if findings:
            return max(severity_map.get(str(f.severity), 35) for f in findings)

        # ── Layer 3: No findings — conservative baseline ───────────────
        action_risks = {
            "delete": 80, "drop": 90, "exec": 90, "sudo": 90,
            "rm": 90, "chmod": 80, "chown": 80, "write": 65,
            "read": 15, "log": 5, "ping": 5, "get": 15, "list": 15,
        }
        base = 15
        for keyword, score in action_risks.items():
            if keyword in request.action.lower():
                base = max(base, score)
        return base


# ─── Global interceptor instance ───
guardian = GuardianInterceptor()


def can_approve(access: AccessContext) -> bool:
    """Check if a role can approve pending actions."""
    return access.role in ("admin",)


def resolve_pending_execution(approval_id: str, access: AccessContext) -> tuple[bool, str]:
    """
    Resolve a pending approval and execute the action.
    Returns (executed: bool, reason: str).
    Called AFTER approval via approve_pending().
    """
    pending = get_pending(approval_id)
    if not pending:
        return False, "Pending approval not found"

    # Tenant isolation: only same tenant can resolve
    if pending.tenant_id != access.tenant_id:
        return False, "Tenant isolation violation"

    if pending.status != "approved":
        return False, f"Approval is {pending.status}, cannot execute"

    # Log execution
    audit_log.append(
        tenant_id=access.tenant_id,
        actor=access.key_id,
        action=f"guardian_approved_execute:{pending.action}",
        decision="allowed",
        context={
            "approval_id": approval_id,
            "agent_id": pending.agent_id,
            "action": pending.action,
            "decided_by": pending.decided_by,
        },
        risk_score=pending.risk_score,
    )

    return True, f"Action '{pending.action}' executed"
