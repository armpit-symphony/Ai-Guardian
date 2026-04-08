"""Append-only, hash-chained audit log with SQLite persistence.

Persistence model:
  • append()  → writes to in-memory index + SQLite (DB is authoritative)
  • get_recent()  → reads from in-memory index (pre-loaded from DB on startup)
  • verify_integrity()  → verifies hash chain using in-memory index

On startup, call audit_log.load_from_db(store) once to reload existing entries
from SQLite. New entries chain correctly off the last DB entry's hash.
The hash algorithm matches the committed implementation exactly:
  _hash_entry(entry) = SHA256(canonical_json({k:v for k,v in entry.items() if k not in ("id","hash")}))
"""

from __future__ import annotations

import hashlib
import json as _json
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .storage import SQLiteStore


# ── Committed hash helpers (matching cb919ae) ─────────────────────────
def canonical_json(data: Any) -> str:
    return _json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


# ── Audit log class ─────────────────────────────────────────────────
class ImmutableAuditLog:
    """
    Append-only, hash-chained audit log.

    Each entry's prev_hash links to the previous entry's hash (or the genesis
    hash for the first entry), making any tampering immediately detectable.

    Persistence:
      • In-memory _entries[tenant_id] — fast read path for the HTTP layer
      • SQLite via store.append_audit_entry() — survives restarts

    On startup, call load_from_db(store) to reload existing entries from SQLite.
    """

    def __init__(self) -> None:
        self._entries: dict[str, list[dict]] = defaultdict(list)
        self._lock = Lock()
        self._genesis_hash = hashlib.sha256(b"GENESIS").hexdigest()
        self._store: "SQLiteStore | None" = None

    @property
    def genesis_hash(self) -> str:
        return self._genesis_hash

    def _hash_entry(self, entry: dict) -> str:
        """Hash an entry for the chain. Excludes mutable 'id' and 'hash' fields.

        Matches committed implementation exactly.
        """
        payload = {k: v for k, v in entry.items() if k not in ("id", "hash")}
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    # ── Startup wiring ────────────────────────────────────────────────

    def configure_store(self, store: "SQLiteStore") -> None:
        """Wire the audit log to the service's DB store. Call once on startup."""
        self._store = store

    def load_from_db(self) -> None:
        """Reload audit entries from the DB into the in-memory index.

        Called once on service startup after the store is wired.
        DB columns are mapped back to the in-memory entry format:
          - 'context'/'metadata' JSON text → dict
          - entries stored WITHOUT tenant_id (tenant is the dict key)
          - 'id' is from DB AUTOINCREMENT (stable for verify_integrity)
        """
        if self._store is None:
            return
        by_tenant = self._store.load_audit_entries()
        with self._lock:
            for tenant_id, entries in by_tenant.items():
                # Entries already in correct in-memory format; assign to tenant
                self._entries[tenant_id] = entries

    # ── Core operations ──────────────────────────────────────────────

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
            entry: dict[str, Any] = {
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

            # Persist to DB immediately (DB is authoritative)
            # Store tenant_id explicitly in DB row for query/filter
            if self._store is not None:
                self._store.append_audit_entry(entry.copy(), tenant_id=tenant_id)

            return entry.copy()

    def get_recent(self, tenant_id: str, limit: int = 100) -> list[dict]:
        entries = self._entries.get(tenant_id, [])
        return entries[-limit:]

    def count(self, tenant_id: str) -> int:
        return len(self._entries.get(tenant_id, []))

    # ── Integrity verification ────────────────────────────────────────

    def verify_integrity(self, tenant_id: str) -> tuple[bool, list[str]]:
        """Verify the hash chain integrity for a tenant."""
        errors: list[str] = []
        entries = self._entries.get(tenant_id, [])
        expected_prev = self._genesis_hash

        for i, entry in enumerate(entries):
            if entry["prev_hash"] != expected_prev:
                errors.append(
                    f"Entry {i + 1}: broken chain link "
                    f"(expected {expected_prev[:16]}... got {entry['prev_hash'][:16]}...)"
                )
            if entry["hash"] != self._hash_entry(entry):
                errors.append(f"Entry {i + 1}: hash mismatch")
            expected_prev = entry["hash"]

        return len(errors) == 0, errors


# ── Global instance ──────────────────────────────────────────────────
audit_log = ImmutableAuditLog()
