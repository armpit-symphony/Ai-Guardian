from __future__ import annotations

import secrets
from datetime import datetime, timezone
from threading import Lock
from typing import Literal, NamedTuple


class PendingApproval(NamedTuple):
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


class GuardianDecision(NamedTuple):
    decision: Literal["allowed", "blocked", "pending_approval"]
    reason: str
    risk_score: int
    requires_approval: bool
    breakglass_used: bool
    approval_id: str | None = None
    proof: str | None = None


# ─── In-memory approval queue ───
_PENDING: dict[str, PendingApproval] = {}
_PENDING_LOCK = Lock()


def create_pending(
    tenant_id: str,
    agent_id: str,
    action: str,
    context: dict,
    actor: str,
    risk_score: int,
) -> PendingApproval:
    approval_id = f"apr_{secrets.token_hex(8)}"
    now = datetime.now(timezone.utc)
    record = PendingApproval(
        approval_id=approval_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        action=action,
        context=context,
        actor=actor,
        risk_score=risk_score,
        created_at=now,
        status="pending",
    )
    with _PENDING_LOCK:
        _PENDING[approval_id] = record
    return record


def get_pending(approval_id: str) -> PendingApproval | None:
    return _PENDING.get(approval_id)


def get_pending_for_tenant(tenant_id: str) -> list[PendingApproval]:
    with _PENDING_LOCK:
        return [
            r for r in _PENDING.values()
            if r.tenant_id == tenant_id and r.status == "pending"
        ]


def approve_pending(approval_id: str, decided_by: str) -> PendingApproval | None:
    now = datetime.now(timezone.utc)
    with _PENDING_LOCK:
        record = _PENDING.get(approval_id)
        if not record or record.status != "pending":
            return None
        updated = record._replace(
            status="approved",
            decision="approved",
            decided_by=decided_by,
            decided_at=now,
        )
        _PENDING[approval_id] = updated
        return updated


def deny_pending(approval_id: str, decided_by: str) -> PendingApproval | None:
    now = datetime.now(timezone.utc)
    with _PENDING_LOCK:
        record = _PENDING.get(approval_id)
        if not record or record.status != "pending":
            return None
        updated = record._replace(
            status="denied",
            decision="denied",
            decided_by=decided_by,
            decided_at=now,
        )
        _PENDING[approval_id] = updated
        return updated


def expire_pending(approval_id: str) -> bool:
    with _PENDING_LOCK:
        record = _PENDING.get(approval_id)
        if not record or record.status != "pending":
            return False
        _PENDING[approval_id] = record._replace(status="expired")
        return True


def count_pending(tenant_id: str) -> int:
    with _PENDING_LOCK:
        return sum(1 for r in _PENDING.values() if r.tenant_id == tenant_id and r.status == "pending")
