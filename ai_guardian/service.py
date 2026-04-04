from __future__ import annotations

import logging
import secrets

from .config import Settings
from .models import (
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
from .storage import SQLiteStore


class GuardianService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = SQLiteStore(settings.database_path)
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
            raise ValueError(f"Unknown agent_id '{request.agent_id}'. Register it before monitoring.")

        allowed_domains = tuple(agent.allowed_domains or self.settings.default_allowed_domains)
        decision, findings, proof = self.policy.evaluate(
            request,
            PolicyContext(
                blocked_domains=self.settings.blocked_domains,
                suspicious_phrases=self.settings.suspicious_phrases,
                allowed_domains=allowed_domains,
            ),
        )
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
