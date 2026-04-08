from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal, NamedTuple


class BreakglassRecord(NamedTuple):
    breakglass_id: str
    approved: bool
    created_at: datetime
    expires_at: datetime
    actor: str
    reason: str
    pin_hash: str
    tenant_id: str
    actions_overridden: list[str]
    status: Literal["active", "used", "expired", "revoked"]


# ─── Breakglass PIN ───
# In production, store the hash in an HSM/KMS
_DEFAULT_PIN_HASH = hashlib.sha256("ai-guardian-breakglass-2026".encode()).hexdigest()

# Active breakglass sessions
_STORE: dict[str, BreakglassRecord] = {}


def verify_pin(pin: str) -> bool:
    """Verify the breakglass PIN."""
    return hashlib.sha256(pin.encode()).hexdigest() == _DEFAULT_PIN_HASH


def create_session(
    tenant_id: str,
    actor: str,
    reason: str,
    pin: str,
    duration_minutes: int = 15,
) -> BreakglassRecord | None:
    """
    Create a breakglass session for emergency override.
    Requires valid PIN + business justification (min 10 chars).
    """
    if not verify_pin(pin):
        return None
    if len(reason) < 10:
        return None

    breakglass_id = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=duration_minutes)

    record = BreakglassRecord(
        breakglass_id=breakglass_id,
        approved=True,
        created_at=now,
        expires_at=expires,
        actor=actor,
        reason=reason,
        pin_hash=hashlib.sha256(pin.encode()).hexdigest(),
        tenant_id=tenant_id,
        actions_overridden=[],
        status="active",
    )
    _STORE[breakglass_id] = record
    return record


def validate_session(breakglass_id: str) -> tuple[bool, str]:
    """Check if a breakglass session is valid."""
    record = _STORE.get(breakglass_id)
    if not record:
        return False, "Breakglass session not found"
    if record.status != "active":
        return False, f"Breakglass session is {record.status}"
    if datetime.now(timezone.utc) > record.expires_at:
        _STORE[breakglass_id] = record._replace(status="expired")
        return False, "Breakglass session has expired"
    return True, "Valid"


def use_session(breakglass_id: str, action: str) -> bool:
    """Record that a breakglass override was used for an action."""
    record = _STORE.get(breakglass_id)
    if not record or record.status != "active":
        return False
    updated = record._replace(
        actions_overridden=record.actions_overridden + [f"{action}@{datetime.now(timezone.utc).isoformat()}"]
    )
    _STORE[breakglass_id] = updated
    return True


def revoke_session(breakglass_id: str) -> bool:
    """Revoke a breakglass session immediately."""
    record = _STORE.get(breakglass_id)
    if not record:
        return False
    _STORE[breakglass_id] = record._replace(status="revoked")
    return True


def get_session(breakglass_id: str) -> BreakglassRecord | None:
    return _STORE.get(breakglass_id)


def list_active_sessions(tenant_id: str) -> list[BreakglassRecord]:
    now = datetime.now(timezone.utc)
    return [
        r for r in _STORE.values()
        if r.tenant_id == tenant_id and r.status == "active" and r.expires_at > now
    ]


def cleanup_expired() -> int:
    """Remove expired breakglass sessions. Returns count cleaned."""
    now = datetime.now(timezone.utc)
    expired_ids = [
        bid for bid, record in _STORE.items()
        if record.status == "active" and now > record.expires_at
    ]
    for bid in expired_ids:
        _STORE[bid] = _STORE[bid]._replace(status="expired")
    return len(expired_ids)
