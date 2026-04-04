from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

from .models import (
    AccessContext,
    AgentRecord,
    AgentRegistration,
    AlertSummary,
    ApiKeyRecord,
    EventRecord,
    TenantCreate,
    TenantOverview,
    TenantRecord,
)


class SQLiteStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.database_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    slug TEXT NOT NULL UNIQUE,
                    contact_email TEXT NOT NULL,
                    plan TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    revoked_at TEXT,
                    FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
                );

                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    description TEXT NOT NULL,
                    allowed_domains TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    anomaly INTEGER NOT NULL,
                    proof TEXT NOT NULL UNIQUE,
                    findings TEXT NOT NULL,
                    context TEXT NOT NULL,
                    source_url TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(agent_id) REFERENCES agents(agent_id),
                    FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
                );
                """
            )
            self._migrate_existing_schema()
            self._conn.commit()

    def _migrate_existing_schema(self) -> None:
        agent_columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(agents)").fetchall()}
        if "tenant_id" not in agent_columns:
            self._conn.execute("ALTER TABLE agents ADD COLUMN tenant_id TEXT")
        event_columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(events)").fetchall()}
        if "tenant_id" not in event_columns:
            self._conn.execute("ALTER TABLE events ADD COLUMN tenant_id TEXT")
        api_key_columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(api_keys)").fetchall()}
        if api_key_columns and "revoked_at" not in api_key_columns:
            self._conn.execute("ALTER TABLE api_keys ADD COLUMN revoked_at TEXT")

    def create_tenant(self, tenant_id: str, payload: TenantCreate) -> TenantRecord:
        created_at = _utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tenants (tenant_id, name, slug, contact_email, plan, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, payload.name, payload.slug, payload.contact_email, payload.plan, created_at.isoformat()),
            )
            self._conn.commit()
        return TenantRecord(tenant_id=tenant_id, created_at=created_at, **payload.model_dump())

    def list_tenants(self) -> list[TenantRecord]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM tenants ORDER BY created_at DESC").fetchall()
        return [_row_to_tenant(row) for row in rows]

    def create_api_key(self, key_id: str, tenant_id: str, name: str, role: str, key_hash: str) -> ApiKeyRecord:
        created_at = _utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO api_keys (key_id, tenant_id, name, role, key_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, tenant_id, name, role, key_hash, created_at.isoformat()),
            )
            self._conn.commit()
        return ApiKeyRecord(
            key_id=key_id,
            tenant_id=tenant_id,
            name=name,
            role=role,
            created_at=created_at,
            last_used_at=None,
            revoked_at=None,
            is_active=True,
        )

    def authenticate_api_key(self, key_hash: str) -> AccessContext | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
            if not row:
                return None
            if row["revoked_at"]:
                return None
            now = _utc_now().isoformat()
            self._conn.execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (now, row["key_id"]))
            self._conn.commit()
        return AccessContext(key_id=row["key_id"], tenant_id=row["tenant_id"], role=row["role"])

    def list_api_keys(self, tenant_id: str) -> list[ApiKeyRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)
            ).fetchall()
        return [
            ApiKeyRecord(
                key_id=row["key_id"],
                tenant_id=row["tenant_id"],
                name=row["name"],
                role=row["role"],
                created_at=datetime.fromisoformat(row["created_at"]),
                last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
                revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
                is_active=row["revoked_at"] is None,
            )
            for row in rows
        ]

    def revoke_api_key(self, tenant_id: str, key_id: str) -> ApiKeyRecord | None:
        revoked_at = _utc_now().isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE tenant_id = ? AND key_id = ? AND revoked_at IS NULL",
                (revoked_at, tenant_id, key_id),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE tenant_id = ? AND key_id = ?", (tenant_id, key_id)
            ).fetchone()
        if not row:
            return None
        return ApiKeyRecord(
            key_id=row["key_id"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            role=row["role"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
            revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
            is_active=row["revoked_at"] is None,
        )

    def create_agent(self, tenant_id: str, agent_id: str, registration: AgentRegistration) -> AgentRecord:
        created_at = _utc_now()
        payload = (
            agent_id,
            tenant_id,
            registration.name,
            registration.owner,
            registration.description,
            json.dumps(registration.allowed_domains),
            created_at.isoformat(),
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agents (agent_id, tenant_id, name, owner, description, allowed_domains, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                payload,
            )
            self._conn.commit()
        return AgentRecord(
            agent_id=agent_id,
            tenant_id=tenant_id,
            created_at=created_at,
            **registration.model_dump(),
        )

    def get_agent(self, tenant_id: str, agent_id: str) -> AgentRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?", (tenant_id, agent_id)
            ).fetchone()
        if not row:
            return None
        return AgentRecord(
            agent_id=row["agent_id"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            owner=row["owner"],
            description=row["description"],
            allowed_domains=json.loads(row["allowed_domains"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def list_agents(self, tenant_id: str) -> list[AgentRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM agents WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)
            ).fetchall()
        return [
            AgentRecord(
                agent_id=row["agent_id"],
                tenant_id=row["tenant_id"],
                name=row["name"],
                owner=row["owner"],
                description=row["description"],
                allowed_domains=json.loads(row["allowed_domains"]),
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def create_event(
        self,
        tenant_id: str,
        agent_id: str,
        action: str,
        decision: str,
        anomaly: bool,
        proof: str,
        findings: list[dict],
        context: dict,
        source_url: str | None,
    ) -> EventRecord:
        created_at = _utc_now()
        payload = (
            tenant_id,
            agent_id,
            action,
            decision,
            int(anomaly),
            proof,
            json.dumps(findings),
            json.dumps(context),
            source_url,
            created_at.isoformat(),
        )
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO events (tenant_id, agent_id, action, decision, anomaly, proof, findings, context, source_url, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                payload,
            )
            self._conn.commit()
            event_id = cursor.lastrowid
        return EventRecord(
            id=event_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=action,
            decision=decision,
            anomaly=anomaly,
            proof=proof,
            findings=findings,
            context=context,
            source_url=source_url,
            created_at=created_at,
        )

    def list_events(self, tenant_id: str, limit: int = 50, decision: str | None = None) -> list[EventRecord]:
        query = "SELECT * FROM events WHERE tenant_id = ?"
        params: tuple[object, ...] = (tenant_id,)
        if decision:
            query += " AND decision = ?"
            params += (decision,)
        query += " ORDER BY created_at DESC LIMIT ?"
        params += (limit,)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [_row_to_event(row) for row in rows]

    def verify_proof(self, tenant_id: str, proof: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM events WHERE tenant_id = ? AND proof = ?", (tenant_id, proof)
            ).fetchone()
        return bool(row)

    def alert_summary(self, tenant_id: str) -> AlertSummary:
        with self._lock:
            totals = self._conn.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END) AS blocked_events,
                    SUM(CASE WHEN decision = 'review' THEN 1 ELSE 0 END) AS review_events,
                    SUM(CASE WHEN anomaly = 1 THEN 1 ELSE 0 END) AS anomalous_events
                FROM events
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchone()
            rows = self._conn.execute("SELECT findings FROM events WHERE tenant_id = ?", (tenant_id,)).fetchall()

        counts: dict[str, int] = {}
        for row in rows:
            for finding in json.loads(row["findings"]):
                code = finding["code"]
                counts[code] = counts.get(code, 0) + 1

        top_findings = [
            {"code": code, "count": count}
            for code, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:5]
        ]
        return AlertSummary(
            total_events=totals["total_events"] or 0,
            blocked_events=totals["blocked_events"] or 0,
            review_events=totals["review_events"] or 0,
            anomalous_events=totals["anomalous_events"] or 0,
            top_findings=top_findings,
        )

    def tenant_overviews(self) -> list[TenantOverview]:
        overviews: list[TenantOverview] = []
        for tenant in self.list_tenants():
            with self._lock:
                agent_count = self._conn.execute(
                    "SELECT COUNT(*) AS count FROM agents WHERE tenant_id = ?", (tenant.tenant_id,)
                ).fetchone()["count"]
            overviews.append(
                TenantOverview(
                    tenant=tenant,
                    agent_count=agent_count,
                    alert_summary=self.alert_summary(tenant.tenant_id),
                )
            )
        return overviews


def _row_to_event(row: sqlite3.Row) -> EventRecord:
    return EventRecord(
        id=row["id"],
        tenant_id=row["tenant_id"],
        agent_id=row["agent_id"],
        action=row["action"],
        decision=row["decision"],
        anomaly=bool(row["anomaly"]),
        proof=row["proof"],
        findings=json.loads(row["findings"]),
        context=json.loads(row["context"]),
        source_url=row["source_url"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _row_to_tenant(row: sqlite3.Row) -> TenantRecord:
    return TenantRecord(
        tenant_id=row["tenant_id"],
        name=row["name"],
        slug=row["slug"],
        contact_email=row["contact_email"],
        plan=row["plan"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
