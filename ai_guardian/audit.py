from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from .models import EvaluationFinding


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


class ImmutableAuditLog:
    """
    Append-only audit log with SHA-256 hash chaining per tenant.
    Each entry hashes the previous entry for tamper detection.
    Used for critical governance events (breakglass, overrides, admin actions).
    """

    def __init__(self):
        self._entries: dict[str, list[dict]] = {}
        self._lock = Lock()
        self._genesis_hash = hashlib.sha256(b"GENESIS").hexdigest()

    @property
    def genesis_hash(self) -> str:
        return self._genesis_hash

    def _hash_entry(self, entry: dict) -> str:
        """Hash an entry for the chain. Excludes mutable 'id' and 'hash' fields."""
        payload = {k: v for k, v in entry.items() if k not in ("id", "hash")}
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def append(
        self,
        tenant_id: str,
        actor: str,
        action: str,
        decision: str,
        context: dict | None = None,
        risk_score: int = 0,
        breakglass_id: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Append a new audit entry with hash chaining for a tenant."""
        with self._lock:
            entries = self._entries.setdefault(tenant_id, [])
            prev_entry = entries[-1] if entries else None
            prev_hash = prev_entry["hash"] if prev_entry else self._genesis_hash

            now = datetime.now(timezone.utc)
            entry = {
                "id": len(entries) + 1,
                "timestamp": now.isoformat(),
                "actor": actor,
                "action": action,
                "decision": decision,
                "context": context or {},
                "risk_score": risk_score,
                "breakglass_id": breakglass_id,
                "metadata": metadata or {},
                "prev_hash": prev_hash,
            }
            entry["hash"] = self._hash_entry(entry)
            entries.append(entry)
            return entry.copy()

    def get_recent(self, tenant_id: str, limit: int = 100) -> list[dict]:
        entries = self._entries.get(tenant_id, [])
        return entries[-limit:]

    def verify_integrity(self, tenant_id: str) -> tuple[bool, list[str]]:
        """Verify the hash chain integrity for a tenant."""
        errors = []
        entries = self._entries.get(tenant_id, [])
        expected_prev = self._genesis_hash

        for i, entry in enumerate(entries):
            if entry["prev_hash"] != expected_prev:
                errors.append(
                    f"Entry {i + 1}: broken chain link "
                    f"(expected {expected_prev[:16]}... got {entry['prev_hash'][:16]}...)"
                )
            calculated = self._hash_entry(entry)
            if entry["hash"] != calculated:
                errors.append(f"Entry {i + 1}: hash mismatch")

            expected_prev = entry["hash"]

        return len(errors) == 0, errors

    def count(self, tenant_id: str) -> int:
        return len(self._entries.get(tenant_id, []))


# Global audit log instance — shared across all tenants
audit_log = ImmutableAuditLog()
