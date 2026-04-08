from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    slug: str = Field(min_length=2, max_length=40, pattern=r"^[a-z0-9-]+$")
    contact_email: str = Field(min_length=5, max_length=120)
    plan: Literal["starter", "growth", "enterprise"] = "starter"


class TenantRecord(TenantCreate):
    tenant_id: str
    created_at: datetime


class ApiKeyRecord(BaseModel):
    key_id: str
    tenant_id: str
    name: str
    role: Literal["admin", "ingest", "viewer"]
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    is_active: bool = True


class AgentRegistration(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    owner: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=500)
    allowed_domains: list[str] = Field(default_factory=list)

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, value: list[str]) -> list[str]:
        return [item.lower().strip() for item in value if item.strip()]


class AgentRecord(AgentRegistration):
    agent_id: str
    tenant_id: str
    created_at: datetime


class MonitorRequest(BaseModel):
    agent_id: str = Field(min_length=3, max_length=64)
    action: str = Field(min_length=2, max_length=400)
    context: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None
    context_checksum: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationFinding(BaseModel):
    code: str
    severity: Literal["low", "medium", "high", "critical"]
    message: str


class MonitorResult(BaseModel):
    event_id: int
    agent_id: str
    tenant_id: str
    decision: Literal["allow", "review", "block"]
    anomaly: bool
    proof: str
    findings: list[EvaluationFinding]
    created_at: datetime


class EventRecord(BaseModel):
    id: int
    tenant_id: str
    agent_id: str
    action: str
    decision: str
    anomaly: bool
    proof: str
    findings: list[dict[str, Any]]
    context: dict[str, Any]
    source_url: str | None
    created_at: datetime


class AlertSummary(BaseModel):
    total_events: int
    blocked_events: int
    review_events: int
    anomalous_events: int
    top_findings: list[dict[str, Any]]


class TenantOverview(BaseModel):
    tenant: TenantRecord
    agent_count: int
    alert_summary: AlertSummary


class TenantBootstrapResponse(BaseModel):
    tenant: TenantRecord
    api_key: str
    key_meta: ApiKeyRecord


class AccessContext(BaseModel):
    key_id: str
    tenant_id: str
    role: Literal["admin", "ingest", "viewer"]


class AccessProfile(BaseModel):
    service_name: str
    tenant: TenantRecord
    api_key: ApiKeyRecord
    capabilities: list[str]


class BreakglassCreate(BaseModel):
    reason: str = Field(..., min_length=10)
    pin: str = Field(..., min_length=6)
    duration_minutes: int = Field(default=15, ge=1, le=60)


class BreakglassRecord(BaseModel):
    breakglass_id: str
    approved: bool
    created_at: datetime
    expires_at: datetime
    actor: str
    reason: str
    tenant_id: str
    actions_overridden: list[str]
    status: Literal["active", "used", "expired", "revoked"]


class BreakglassResponse(BaseModel):
    breakglass_id: str
    approved: bool
    expires_at: datetime
    actor: str


class AuditRecord(BaseModel):
    id: int
    timestamp: datetime
    actor: str
    action: str
    decision: str
    context: dict
    risk_score: int
    breakglass_id: str | None
    hash: str
    prev_hash: str


class AuditVerifyResponse(BaseModel):
    valid: bool
    total_entries: int
    errors: list[str]


# ─── Enforcement Models ───
class GuardianDecisionResponse(BaseModel):
    decision: Literal["allowed", "blocked", "pending_approval"]
    reason: str
    risk_score: int = Field(ge=0, le=100)
    requires_approval: bool
    breakglass_used: bool
    approval_id: str | None = None
    proof: str | None = None


class PendingApprovalRecord(BaseModel):
    approval_id: str
    tenant_id: str
    agent_id: str
    action: str
    context: dict
    actor: str
    risk_score: int
    created_at: datetime
    status: Literal["pending", "approved", "denied", "expired"]
    decision: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None


class ApprovalDecideRequest(BaseModel):
    approval_id: str
    decision: Literal["approve", "deny"]
