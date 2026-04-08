from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import TYPE_CHECKING, Literal, NamedTuple

if TYPE_CHECKING:
    from .storage import SQLiteStore


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
    used: bool = False  # one-time use: True after first successful use


# ─── Breakglass PIN ───
# In production, store the hash in an HSM/KMS
_DEFAULT_PIN_HASH = hashlib.sha256("ai-guardian-breakglass-2026".encode()).hexdigest()

# Active breakglass sessions — local cache rebuilt from DB on startup
_STORE: dict[str, BreakglassRecord] = {}
_STORE_LOCK = Lock()

# Module-level store reference (set via configure_store())
_store_ref: "SQLiteStore | None" = None

# Current PIN hash (loaded from DB on startup; falls back to compiled default)
_pin_hash_ref: str = _DEFAULT_PIN_HASH


def configure_store(store: "SQLiteStore") -> None:
    """Wire breakglass to the service's DB store. Call once on startup."""
    global _store_ref
    _store_ref = store


def configure_pin_hash(pin_hash: str | None) -> None:
    """Set the active PIN hash. None = use compiled default."""
    global _pin_hash_ref
    _pin_hash_ref = pin_hash if pin_hash else _DEFAULT_PIN_HASH


def load_from_db() -> None:
    """Rebuild in-memory cache from DB — called once on service startup."""
    global _pin_hash_ref
    if _store_ref is None:
        return
    # Load all non-expired sessions so we can enforce used/revoked state
    rows = _store_ref.list_breakglass_sessions(tenant_id="", status=None)
    with _STORE_LOCK:
        for row in rows:
            created = datetime.fromisoformat(row["created_at"])
            expires = datetime.fromisoformat(row["expires_at"])
            actions = row["actions_overridden"]
            if isinstance(actions, str):
                actions = json.loads(actions)
            _STORE[row["breakglass_id"]] = BreakglassRecord(
                breakglass_id=row["breakglass_id"],
                approved=bool(row["approved"]),
                created_at=created,
                expires_at=expires,
                actor=row["actor"],
                reason=row["reason"],
                pin_hash=row["pin_hash"],
                tenant_id=row["tenant_id"],
                actions_overridden=actions or [],
                status=row["status"],
                used=bool(row.get("used", 0)),
            )
    # Load PIN hash from DB config (fall back to compiled default)
    db_hash = _store_ref.get_breakglass_config("pin_hash")
    _pin_hash_ref = db_hash if db_hash else _DEFAULT_PIN_HASH


def verify_pin(pin: str) -> bool:
    """Verify the breakglass PIN against the currently configured hash."""
    return hashlib.sha256(pin.encode()).hexdigest() == _pin_hash_ref


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
    now_str = now.isoformat()
    expires = now + timedelta(minutes=duration_minutes)
    expires_str = expires.isoformat()
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()

    record = BreakglassRecord(
        breakglass_id=breakglass_id,
        approved=True,
        created_at=now,
        expires_at=expires,
        actor=actor,
        reason=reason,
        pin_hash=pin_hash,
        tenant_id=tenant_id,
        actions_overridden=[],
        status="active",
        used=False,
    )

    # DB authoritative — always write first
    if _store_ref is not None:
        _store_ref.create_breakglass_session(
            breakglass_id=breakglass_id,
            tenant_id=tenant_id,
            approved=True,
            created_at=now_str,
            expires_at=expires_str,
            actor=actor,
            reason=reason,
            pin_hash=pin_hash,
            actions_overridden=[],
        )

    with _STORE_LOCK:
        _STORE[breakglass_id] = record
    return record


def validate_session(breakglass_id: str) -> tuple[bool, str]:
    """Check if a breakglass session is valid for use (not used, not expired, active)."""
    # DB authoritative for status
    if _store_ref is not None:
        row = _store_ref.get_breakglass_session(breakglass_id)
        if not row:
            return False, "Breakglass session not found"
        if row["status"] != "active":
            return False, f"Breakglass session is {row['status']}"
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) > expires:
            _store_ref.update_breakglass_session(breakglass_id, status="expired")
            with _STORE_LOCK:
                if breakglass_id in _STORE:
                    _STORE[breakglass_id] = _STORE[breakglass_id]._replace(status="expired")
            return False, "Breakglass session has expired"
        # One-time use: reject if already used
        if row.get("used", 0) or row["status"] == "used":
            return False, "Breakglass session has already been used"
        return True, "Valid"

    # Fallback: in-memory
    record = _STORE.get(breakglass_id)
    if not record:
        return False, "Breakglass session not found"
    if record.status != "active":
        return False, f"Breakglass session is {record.status}"
    if datetime.now(timezone.utc) > record.expires_at:
        with _STORE_LOCK:
            _STORE[breakglass_id] = record._replace(status="expired")
        return False, "Breakglass session has expired"
    if record.used:
        return False, "Breakglass session has already been used"
    return True, "Valid"


def use_session(breakglass_id: str, action: str) -> bool:
    """Record that a breakglass override was used for an action. One-time use only."""
    now = datetime.now(timezone.utc)

    # DB authoritative
    if _store_ref is not None:
        row = _store_ref.get_breakglass_session(breakglass_id)
        if not row or row["status"] != "active":
            return False
        if row.get("used", 0):
            return False  # already used

        # Get current actions_overridden
        actions = row["actions_overridden"]
        if isinstance(actions, str):
            actions = json.loads(actions)
        actions = list(actions) + [f"{action}@{now.isoformat()}"]

        _store_ref.update_breakglass_session(
            breakglass_id,
            status="used",
            actions_overridden=actions,
            used=True,
        )
        with _STORE_LOCK:
            if breakglass_id in _STORE:
                _STORE[breakglass_id] = _STORE[breakglass_id]._replace(
                    status="used",
                    actions_overridden=actions,
                    used=True,
                )
        return True

    # Fallback: in-memory
    record = _STORE.get(breakglass_id)
    if not record or record.status != "active" or record.used:
        return False
    updated = record._replace(
        status="used",
        used=True,
        actions_overridden=record.actions_overridden + [f"{action}@{now.isoformat()}"],
    )
    with _STORE_LOCK:
        _STORE[breakglass_id] = updated
    return True


def revoke_session(breakglass_id: str) -> bool:
    """Revoke a breakglass session immediately."""
    if _store_ref is not None:
        row = _store_ref.update_breakglass_session(breakglass_id, status="revoked")
        if not row:
            return False
        with _STORE_LOCK:
            if breakglass_id in _STORE:
                _STORE[breakglass_id] = _STORE[breakglass_id]._replace(status="revoked")
        return True

    # Fallback: in-memory
    record = _STORE.get(breakglass_id)
    if not record:
        return False
    with _STORE_LOCK:
        _STORE[breakglass_id] = record._replace(status="revoked")
    return True


def get_session(breakglass_id: str) -> BreakglassRecord | None:
    if _store_ref is not None:
        row = _store_ref.get_breakglass_session(breakglass_id)
        if not row:
            return None
        created = datetime.fromisoformat(row["created_at"])
        expires = datetime.fromisoformat(row["expires_at"])
        actions = row["actions_overridden"]
        if isinstance(actions, str):
            actions = json.loads(actions)
        return BreakglassRecord(
            breakglass_id=row["breakglass_id"],
            approved=bool(row["approved"]),
            created_at=created,
            expires_at=expires,
            actor=row["actor"],
            reason=row["reason"],
            pin_hash=row["pin_hash"],
            tenant_id=row["tenant_id"],
            actions_overridden=actions or [],
            status=row["status"],
            used=bool(row.get("used", 0)),
        )
    return _STORE.get(breakglass_id)


def list_active_sessions(tenant_id: str) -> list[BreakglassRecord]:
    now = datetime.now(timezone.utc)
    if _store_ref is not None:
        rows = _store_ref.list_breakglass_sessions(tenant_id, status="active")
        result = []
        for row in rows:
            expires = datetime.fromisoformat(row["expires_at"])
            if expires > now:
                created = datetime.fromisoformat(row["created_at"])
                actions = row["actions_overridden"]
                if isinstance(actions, str):
                    actions = json.loads(actions)
                result.append(BreakglassRecord(
                    breakglass_id=row["breakglass_id"],
                    approved=bool(row["approved"]),
                    created_at=created,
                    expires_at=expires,
                    actor=row["actor"],
                    reason=row["reason"],
                    pin_hash=row["pin_hash"],
                    tenant_id=row["tenant_id"],
                    actions_overridden=actions or [],
                    status=row["status"],
                    used=bool(row.get("used", 0)),
                ))
        return result
    with _STORE_LOCK:
        return [
            r for r in _STORE.values()
            if r.tenant_id == tenant_id and r.status == "active" and r.expires_at > now
        ]


def cleanup_expired() -> int:
    """Remove expired breakglass sessions. Returns count cleaned."""
    now = datetime.now(timezone.utc)
    if _store_ref is not None:
        rows = _store_ref.list_breakglass_sessions(tenant_id="", status="active")
        expired_ids = []
        for row in rows:
            expires = datetime.fromisoformat(row["expires_at"])
            if now > expires:
                expired_ids.append(row["breakglass_id"])
        for bid in expired_ids:
            _store_ref.update_breakglass_session(bid, status="expired")
            with _STORE_LOCK:
                if bid in _STORE:
                    _STORE[bid] = _STORE[bid]._replace(status="expired")
        return len(expired_ids)

    expired_ids = [
        bid for bid, record in _STORE.items()
        if record.status == "active" and now > record.expires_at
    ]
    with _STORE_LOCK:
        for bid in expired_ids:
            _STORE[bid] = _STORE[bid]._replace(status="expired")
    return len(expired_ids)


def rotate_pin(current_pin: str, new_pin: str, actor: str) -> bool:
    """
    Rotate the breakglass PIN.

    Requires the current PIN to authorize the change, sets a new PIN,
    persists the new hash to DB, updates the in-memory ref, and writes
    an audit entry.

    Returns True on success, False if current PIN is wrong or new PIN
    is invalid.
    """
    if not verify_pin(current_pin):
        return False
    if len(new_pin) < 6:
        return False
    if len(new_pin) > 64:
        return False

    new_hash = hashlib.sha256(new_pin.encode()).hexdigest()
    if _store_ref is not None:
        _store_ref.set_breakglass_config("pin_hash", new_hash, updated_by=actor)
    global _pin_hash_ref
    _pin_hash_ref = new_hash
    return True


def get_current_pin_hash() -> str:
    """Return the currently active PIN hash (for read-only verification)."""
    return _pin_hash_ref
