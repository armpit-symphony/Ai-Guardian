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
