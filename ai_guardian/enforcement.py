from __future__ import annotations

import secrets
from datetime import datetime, timezone
from threading import Lock
from typing import TYPE_CHECKING, Literal, NamedTuple

if TYPE_CHECKING:
    from .storage import SQLiteStore


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


# ─── In-memory approval queue (local cache rebuilt from DB on startup) ────────
_PENDING: dict[str, PendingApproval] = {}
_PENDING_LOCK = Lock()

# Module-level store reference (set via configure_store())
_store_ref: "SQLiteStore | None" = None


def configure_store(store: "SQLiteStore") -> None:
    """Wire enforcement to the service's DB store. Call once on startup."""
    global _store_ref
    _store_ref = store


def load_from_db() -> None:
    """Rebuild in-memory cache from DB — called once on service startup."""
    if _store_ref is None:
        return
    rows = _store_ref.list_pending_approvals(tenant_id="", status=None)
    with _PENDING_LOCK:
        for row in rows:
            # Only cache pending entries (resolved ones don't need in-memory tracking)
            if row["status"] == "pending":
                created = datetime.fromisoformat(row["created_at"])
                _PENDING[row["approval_id"]] = PendingApproval(
                    approval_id=row["approval_id"],
                    tenant_id=row["tenant_id"],
                    agent_id=row["agent_id"],
                    action=row["action"],
                    context=row["context"] if isinstance(row["context"], dict) else {},
                    actor=row["actor"],
                    risk_score=row["risk_score"],
                    created_at=created,
                    status="pending",
                )


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
    now_str = now.isoformat()
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
    # DB authoritative — always write first
    if _store_ref is not None:
        _store_ref.create_pending_approval(
            approval_id=approval_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=action,
            context=context,
            actor=actor,
            risk_score=risk_score,
            created_at=now_str,
        )
    with _PENDING_LOCK:
        _PENDING[approval_id] = record
    return record


def get_pending(approval_id: str) -> PendingApproval | None:
    # DB authoritative; in-memory is secondary cache
    if _store_ref is not None:
        row = _store_ref.get_pending_approval(approval_id)
        if row:
            created = datetime.fromisoformat(row["created_at"])
            decided_at = datetime.fromisoformat(row["decided_at"]) if row.get("decided_at") else None
            return PendingApproval(
                approval_id=row["approval_id"],
                tenant_id=row["tenant_id"],
                agent_id=row["agent_id"],
                action=row["action"],
                context=row["context"] if isinstance(row["context"], dict) else {},
                actor=row["actor"],
                risk_score=row["risk_score"],
                created_at=created,
                status=row["status"],
                decision=row.get("decision"),
                decided_by=row.get("decided_by"),
                decided_at=decided_at,
            )
    return _PENDING.get(approval_id)


def get_pending_for_tenant(tenant_id: str) -> list[PendingApproval]:
    # DB authoritative
    if _store_ref is not None:
        rows = _store_ref.list_pending_approvals(tenant_id, status="pending")
        result = []
        for row in rows:
            created = datetime.fromisoformat(row["created_at"])
            result.append(PendingApproval(
                approval_id=row["approval_id"],
                tenant_id=row["tenant_id"],
                agent_id=row["agent_id"],
                action=row["action"],
                context=row["context"] if isinstance(row["context"], dict) else {},
                actor=row["actor"],
                risk_score=row["risk_score"],
                created_at=created,
                status="pending",
            ))
        return result
    with _PENDING_LOCK:
        return [
            r for r in _PENDING.values()
            if r.tenant_id == tenant_id and r.status == "pending"
        ]


def approve_pending(approval_id: str, decided_by: str) -> PendingApproval | None:
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()
    # DB first
    if _store_ref is not None:
        row = _store_ref.update_pending_approval(
            approval_id=approval_id,
            status="approved",
            decision="approved",
            decided_by=decided_by,
            decided_at=now_str,
        )
        if not row:
            return None
        created = datetime.fromisoformat(row["created_at"])
        decided = datetime.fromisoformat(row["decided_at"]) if row.get("decided_at") else None
        updated = PendingApproval(
            approval_id=row["approval_id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            context=row["context"] if isinstance(row["context"], dict) else {},
            actor=row["actor"],
            risk_score=row["risk_score"],
            created_at=created,
            status="approved",
            decision="approved",
            decided_by=decided_by,
            decided_at=decided,
        )
        with _PENDING_LOCK:
            _PENDING[approval_id] = updated
        return updated
    # Fallback: in-memory only
    with _PENDING_LOCK:
        record = _PENDING.get(approval_id)
        if not record or record.status != "pending":
            return None
        updated = record._replace(
            status="approved", decision="approved", decided_by=decided_by, decided_at=now,
        )
        _PENDING[approval_id] = updated
        return updated


def deny_pending(approval_id: str, decided_by: str) -> PendingApproval | None:
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()
    if _store_ref is not None:
        row = _store_ref.update_pending_approval(
            approval_id=approval_id,
            status="denied",
            decision="denied",
            decided_by=decided_by,
            decided_at=now_str,
        )
        if not row:
            return None
        created = datetime.fromisoformat(row["created_at"])
        decided = datetime.fromisoformat(row["decided_at"]) if row.get("decided_at") else None
        updated = PendingApproval(
            approval_id=row["approval_id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            context=row["context"] if isinstance(row["context"], dict) else {},
            actor=row["actor"],
            risk_score=row["risk_score"],
            created_at=created,
            status="denied",
            decision="denied",
            decided_by=decided_by,
            decided_at=decided,
        )
        with _PENDING_LOCK:
            _PENDING[approval_id] = updated
        return updated
    with _PENDING_LOCK:
        record = _PENDING.get(approval_id)
        if not record or record.status != "pending":
            return None
        updated = record._replace(
            status="denied", decision="denied", decided_by=decided_by, decided_at=now,
        )
        _PENDING[approval_id] = updated
        return updated


def expire_pending(approval_id: str) -> bool:
    if _store_ref is not None:
        row = _store_ref.update_pending_approval(
            approval_id=approval_id, status="expired",
        )
        if not row:
            return False
        with _PENDING_LOCK:
            if approval_id in _PENDING:
                _PENDING[approval_id] = _PENDING[approval_id]._replace(status="expired")
        return True
    with _PENDING_LOCK:
        record = _PENDING.get(approval_id)
        if not record or record.status != "pending":
            return False
        _PENDING[approval_id] = record._replace(status="expired")
        return True


def count_pending(tenant_id: str) -> int:
    if _store_ref is not None:
        return _store_ref.count_pending_approvals(tenant_id)
    with _PENDING_LOCK:
        return sum(1 for r in _PENDING.values() if r.tenant_id == tenant_id and r.status == "pending")
