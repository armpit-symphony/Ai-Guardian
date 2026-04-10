from __future__ import annotations

import uuid
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


class MonitorEventRecord(BaseModel):
    """
    Raw monitor event record — written to monitor_events at ingest time,
    before evaluation runs. This is forensic ground truth.
    """
    id: uuid.UUID
    tenant_id: str
    agent_id: str
    action: str
    source_url: str | None
    context: dict[str, Any]
    metadata: dict[str, Any]
    received_at: datetime
    request_id: uuid.UUID
    created_at: datetime


class EvaluationResultRecord(BaseModel):
    """
    Guardian evaluation decision — written to evaluation_results after
    policy evaluation completes. Linked to monitor_events by monitor_event_id.
    """
    id: uuid.UUID
    monitor_event_id: uuid.UUID
    tenant_id: str
    decision: str
    score: float | None
    reasons: list[dict[str, Any]]
    policy_version: str | None
    evaluator_name: str | None
    created_at: datetime


class FindingRecord(BaseModel):
    """
    Normalized finding — unified schema for all product sources.
    Written after monitor_events and evaluation_results are committed.
    """
    id: uuid.UUID
    tenant_id: str
    monitor_event_id: uuid.UUID
    evaluation_result_id: uuid.UUID | None
    source: str
    source_finding_id: str | None
    type: str
    severity: str
    confidence: float | None
    title: str
    description: str | None
    service: str | None
    resource: str | None
    evidence: list[dict[str, Any]]
    context: dict[str, Any]
    raw_payload: dict[str, Any]
    first_seen_at: datetime
    created_at: datetime
