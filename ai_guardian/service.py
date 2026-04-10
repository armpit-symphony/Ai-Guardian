from __future__ import annotations

import logging
import secrets
import uuid
from csv import DictWriter
from datetime import datetime, timezone
from io import StringIO

from .config import Settings
from .models import (
    AccessProfile,
    AccessContext,
    AgentRecord,
    AgentRegistration,
    ApiKeyRecord,
    MonitorRequest,
    MonitorResult,
    TenantBootstrapResponse,
    TenantCreate,
    TenantOverview,
    TenantRecord,
)
from .notifications import AlertDispatcher
from .policy import PolicyContext, PolicyEngine
from .security import generate_api_key, hash_api_key
from .storage import create_store


class GuardianService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = create_store(settings.database_path, settings.database_url)
        self.policy = PolicyEngine()
        self.alerts = AlertDispatcher(settings.webhook_urls)
        self.logger = logging.getLogger("ai_guardian")

    def bootstrap_tenant(self, payload: TenantCreate, key_name: str = "Primary API key") -> TenantBootstrapResponse:
        tenant_id = f"ten_{secrets.token_hex(8)}"
        tenant = self.store.create_tenant(tenant_id=tenant_id, payload=payload)
        api_key = generate_api_key()
        key_meta = self.store.create_api_key(
            key_id=f"key_{secrets.token_hex(8)}",
            tenant_id=tenant.tenant_id,
            name=key_name,
            role="admin",
            key_hash=hash_api_key(api_key),
        )
        return TenantBootstrapResponse(tenant=tenant, api_key=api_key, key_meta=key_meta)

    def authenticate(self, api_key: str) -> AccessContext | None:
        return self.store.authenticate_api_key(hash_api_key(api_key))

    def list_tenants(self) -> list[TenantRecord]:
        return self.store.list_tenants()

    def tenant_overviews(self) -> list[TenantOverview]:
        return self.store.tenant_overviews()

    def create_api_key(self, access: AccessContext, name: str, role: str) -> tuple[str, ApiKeyRecord]:
        api_key = generate_api_key()
        record = self.store.create_api_key(
            key_id=f"key_{secrets.token_hex(8)}",
            tenant_id=access.tenant_id,
            name=name,
            role=role,
            key_hash=hash_api_key(api_key),
        )
        return api_key, record

    def revoke_api_key(self, access: AccessContext, key_id: str) -> ApiKeyRecord | None:
        return self.store.revoke_api_key(access.tenant_id, key_id)

    def rotate_api_key(self, access: AccessContext, key_id: str, replacement_name: str | None = None) -> tuple[str, ApiKeyRecord]:
        existing = next((item for item in self.store.list_api_keys(access.tenant_id) if item.key_id == key_id), None)
        if not existing:
            raise ValueError(f"Unknown key_id '{key_id}'.")
        self.store.revoke_api_key(access.tenant_id, key_id)
        api_key = generate_api_key()
        record = self.store.create_api_key(
            key_id=f"key_{secrets.token_hex(8)}",
            tenant_id=access.tenant_id,
            name=replacement_name or f"{existing.name} rotated",
            role=existing.role,
            key_hash=hash_api_key(api_key),
        )
        return api_key, record

    def list_api_keys(self, access: AccessContext) -> list[ApiKeyRecord]:
        return self.store.list_api_keys(access.tenant_id)

    def access_profile(self, access: AccessContext) -> AccessProfile:
        tenant = self.store.get_tenant(access.tenant_id)
        api_key = self.store.get_api_key(access.tenant_id, access.key_id)
        if not tenant or not api_key:
            raise ValueError("Access context could not be resolved.")
        capabilities = {
            "admin": ["tenant:read", "keys:write", "agents:write", "monitor:write", "events:read", "events:export"],
            "ingest": ["agents:write", "monitor:write"],
            "viewer": ["tenant:read", "events:read", "events:export"],
        }[access.role]
        return AccessProfile(service_name=self.settings.service_name, tenant=tenant, api_key=api_key, capabilities=capabilities)

    def register_agent(self, access: AccessContext, registration: AgentRegistration) -> AgentRecord:
        agent_id = f"agt_{secrets.token_hex(8)}"
        return self.store.create_agent(tenant_id=access.tenant_id, agent_id=agent_id, registration=registration)

    def list_agents(self, access: AccessContext) -> list[AgentRecord]:
        return self.store.list_agents(access.tenant_id)

    def get_agent(self, access: AccessContext, agent_id: str) -> AgentRecord | None:
        return self.store.get_agent(access.tenant_id, agent_id)

    def monitor(self, access: AccessContext, request: MonitorRequest) -> MonitorResult:
        agent = self.store.get_agent(access.tenant_id, request.agent_id)
        if not agent:
            # Auto-register unknown agents for Phase 1 flexibility.
            # In production, agents should be registered out-of-band.
            try:
                self.store.create_agent(
                    access.tenant_id,
                    request.agent_id,  # Use the provided agent_id directly
                    AgentRegistration(
                        name=request.agent_id,
                        owner=request.agent_id,
                    )
                )
            except Exception:
                pass  # Another worker may have registered it first

        # Step 1: Persist raw monitor event BEFORE evaluation.
        # This is forensic ground truth — evaluation must not be able to delete it.
        event_id = uuid.uuid4()
        request_id = uuid.uuid4()
        received_at = datetime.now(timezone.utc)
        try:
            self.store.create_monitor_event(
                event_id=event_id,
                tenant_id=access.tenant_id,
                agent_id=request.agent_id,
                action=request.action,
                source_url=request.source_url,
                context=request.context or {},
                metadata=request.metadata or {},
                received_at=received_at,
                request_id=request_id,
            )
        except Exception:
            self.logger.exception("Failed to persist raw monitor event — continuing evaluation")
            # Raw event persistence failure must not block evaluation.

        # Step 2: Evaluate policy (existing logic unchanged)
        allowed_domains = tuple(agent.allowed_domains or self.settings.default_allowed_domains)
        decision, findings, proof = self.policy.evaluate(
            request,
            PolicyContext(
                blocked_domains=self.settings.blocked_domains,
                suspicious_phrases=self.settings.suspicious_phrases,
                allowed_domains=allowed_domains,
            ),
        )

        # Step 3: Persist evaluation result — linked to monitor_events row.
        # Written AFTER evaluation; isolated from raw event persistence.
        evaluation_result_id: uuid.UUID | None = None
        try:
            evaluation_result_id = uuid.uuid4()
            self.store.create_evaluation_result(
                result_id=evaluation_result_id,
                monitor_event_id=event_id,
                tenant_id=access.tenant_id,
                decision=decision,
                score=None,  # score field reserved for future confidence/risk scoring
                reasons=[f.model_dump() for f in findings],
                policy_version=getattr(self.settings, "policy_version", None),
                evaluator_name="default",
                created_at=datetime.now(timezone.utc),
            )
        except Exception:
            self.logger.exception("Failed to persist evaluation result — continuing")

        # Step 4: Persist normalized findings — linked to both monitor_events and evaluation_results.
        # Written after both layers are committed. Each finding is independent.
        if findings:
            try:
                now = datetime.now(timezone.utc)
                normalized = [
                    {
                        "type": "policy_finding",
                        "severity": f.severity,
                        "title": f.message[:120],
                        "description": f.message,
                        "source_finding_id": f.code,
                        "resource": request.source_url,
                        "context": {"action": request.action, "agent_id": request.agent_id},
                        "evidence": [],
                        "raw_payload": {
                            "decision": decision,
                            "proof": proof,
                            "finding_code": f.code,
                            "finding_severity": f.severity,
                            "finding_message": f.message,
                        },
                    }
                    for f in findings
                ]
                self.store.create_findings(
                    tenant_id=access.tenant_id,
                    monitor_event_id=event_id,
                    evaluation_result_id=evaluation_result_id,
                    findings=normalized,
                    source="ai-guardian",
                    raw_payload=request.context or {},
                    created_at=now,
                )
            except Exception:
                self.logger.exception("Failed to persist normalized findings — continuing")

        event = self.store.create_event(
            tenant_id=access.tenant_id,
            agent_id=request.agent_id,
            action=request.action,
            decision=decision,
            anomaly=decision != "allow",
            proof=proof,
            findings=[item.model_dump() for item in findings],
            context=request.context,
            source_url=request.source_url,
        )
        if decision in {"review", "block"} and self.alerts.webhook_urls:
            payload = {
                "tenant_id": access.tenant_id,
                "agent_id": request.agent_id,
                "decision": decision,
                "action": request.action,
                "event_id": event.id,
                "proof": proof,
                "findings": [item.model_dump() for item in findings],
            }
            self.alerts.dispatch(payload)
            self.logger.info("Dispatched alert webhooks", extra={"tenant_id": access.tenant_id, "event_id": event.id})
        return MonitorResult(
            event_id=event.id,
            tenant_id=event.tenant_id,
            agent_id=event.agent_id,
            decision=event.decision,  # type: ignore[arg-type]
            anomaly=event.anomaly,
            proof=event.proof,
            findings=findings,
            created_at=event.created_at,
        )

    def verify_proof(self, access: AccessContext, proof: str) -> bool:
        return self.store.verify_proof(access.tenant_id, proof)

    def export_events_csv(self, access: AccessContext, decision: str | None = None, limit: int = 500) -> str:
        events = self.store.list_events(access.tenant_id, limit=limit, decision=decision)
        buffer = StringIO()
        writer = DictWriter(
            buffer,
            fieldnames=["id", "tenant_id", "agent_id", "action", "decision", "anomaly", "proof", "source_url", "created_at", "findings"],
        )
        writer.writeheader()
        for event in events:
            writer.writerow(
                {
                    "id": event.id,
                    "tenant_id": event.tenant_id,
                    "agent_id": event.agent_id,
                    "action": event.action,
                    "decision": event.decision,
                    "anomaly": event.anomaly,
                    "proof": event.proof,
                    "source_url": event.source_url or "",
                    "created_at": event.created_at.isoformat(),
                    "findings": ",".join(item["code"] for item in event.findings),
                }
            )
        return buffer.getvalue()
