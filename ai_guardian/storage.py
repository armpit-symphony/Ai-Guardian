from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

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

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover
    psycopg = None
    dict_row = None


SQLITE_SCHEMA = """
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

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    contact_email TEXT NOT NULL,
    plan TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    name TEXT NOT NULL,
    owner TEXT NOT NULL,
    description TEXT NOT NULL,
    allowed_domains JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    anomaly BOOLEAN NOT NULL,
    proof TEXT NOT NULL UNIQUE,
    findings JSONB NOT NULL,
    context JSONB NOT NULL,
    source_url TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"""


class SQLiteStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.database_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            self._conn.executescript(SQLITE_SCHEMA)
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
                "INSERT INTO tenants (tenant_id, name, slug, contact_email, plan, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (tenant_id, payload.name, payload.slug, payload.contact_email, payload.plan, created_at.isoformat()),
            )
            self._conn.commit()
        return TenantRecord(tenant_id=tenant_id, created_at=created_at, **payload.model_dump())

    def list_tenants(self) -> list[TenantRecord]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM tenants ORDER BY created_at DESC").fetchall()
        return [_row_to_tenant(dict(row)) for row in rows]

    def create_api_key(self, key_id: str, tenant_id: str, name: str, role: str, key_hash: str) -> ApiKeyRecord:
        created_at = _utc_now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys (key_id, tenant_id, name, role, key_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
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
            if not row or row["revoked_at"]:
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
        return [_row_to_api_key(dict(row)) for row in rows]

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
        return _row_to_api_key(dict(row)) if row else None

    def create_agent(self, tenant_id: str, agent_id: str, registration: AgentRegistration) -> AgentRecord:
        created_at = _utc_now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO agents (agent_id, tenant_id, name, owner, description, allowed_domains, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    agent_id,
                    tenant_id,
                    registration.name,
                    registration.owner,
                    registration.description,
                    json.dumps(registration.allowed_domains),
                    created_at.isoformat(),
                ),
            )
            self._conn.commit()
        return AgentRecord(agent_id=agent_id, tenant_id=tenant_id, created_at=created_at, **registration.model_dump())

    def get_agent(self, tenant_id: str, agent_id: str) -> AgentRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?", (tenant_id, agent_id)
            ).fetchone()
        return _row_to_agent(dict(row)) if row else None

    def list_agents(self, tenant_id: str) -> list[AgentRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM agents WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)
            ).fetchall()
        return [_row_to_agent(dict(row)) for row in rows]

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
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO events (tenant_id, agent_id, action, decision, anomaly, proof, findings, context, source_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
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
                ),
            )
            self._conn.commit()
            event_id = cursor.lastrowid
        return EventRecord(id=event_id, tenant_id=tenant_id, agent_id=agent_id, action=action, decision=decision, anomaly=anomaly, proof=proof, findings=findings, context=context, source_url=source_url, created_at=created_at)

    def list_events(self, tenant_id: str, limit: int = 50, decision: str | None = None) -> list[EventRecord]:
        query = "SELECT * FROM events WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if decision:
            query += " AND decision = ?"
            params.append(decision)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [_row_to_event(dict(row)) for row in rows]

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
                SELECT COUNT(*) AS total_events,
                       SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END) AS blocked_events,
                       SUM(CASE WHEN decision = 'review' THEN 1 ELSE 0 END) AS review_events,
                       SUM(CASE WHEN anomaly = 1 THEN 1 ELSE 0 END) AS anomalous_events
                FROM events WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchone()
            rows = self._conn.execute("SELECT findings FROM events WHERE tenant_id = ?", (tenant_id,)).fetchall()
        return _build_alert_summary(dict(totals), [json.loads(row["findings"]) for row in rows])

    def tenant_overviews(self) -> list[TenantOverview]:
        overviews: list[TenantOverview] = []
        for tenant in self.list_tenants():
            with self._lock:
                agent_count = self._conn.execute(
                    "SELECT COUNT(*) AS count FROM agents WHERE tenant_id = ?", (tenant.tenant_id,)
                ).fetchone()["count"]
            overviews.append(TenantOverview(tenant=tenant, agent_count=agent_count, alert_summary=self.alert_summary(tenant.tenant_id)))
        return overviews


class PostgresStore:
    def __init__(self, database_url: str):
        if psycopg is None:  # pragma: no cover
            raise RuntimeError("psycopg is required for PostgreSQL support. Install psycopg[binary].")
        self.database_url = database_url
        self._initialize()

    def _connect(self):
        return psycopg.connect(self.database_url, row_factory=dict_row)

    def _initialize(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(POSTGRES_SCHEMA)
            conn.commit()

    def create_tenant(self, tenant_id: str, payload: TenantCreate) -> TenantRecord:
        created_at = _utc_now()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, name, slug, contact_email, plan, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                    (tenant_id, payload.name, payload.slug, payload.contact_email, payload.plan, created_at),
                )
            conn.commit()
        return TenantRecord(tenant_id=tenant_id, created_at=created_at, **payload.model_dump())

    def list_tenants(self) -> list[TenantRecord]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM tenants ORDER BY created_at DESC")
                rows = cur.fetchall()
        return [_row_to_tenant(row) for row in rows]

    def create_api_key(self, key_id: str, tenant_id: str, name: str, role: str, key_hash: str) -> ApiKeyRecord:
        created_at = _utc_now()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO api_keys (key_id, tenant_id, name, role, key_hash, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                    (key_id, tenant_id, name, role, key_hash, created_at),
                )
            conn.commit()
        return ApiKeyRecord(key_id=key_id, tenant_id=tenant_id, name=name, role=role, created_at=created_at, last_used_at=None, revoked_at=None, is_active=True)

    def authenticate_api_key(self, key_hash: str) -> AccessContext | None:
        now = _utc_now()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM api_keys WHERE key_hash = %s", (key_hash,))
                row = cur.fetchone()
                if not row or row["revoked_at"]:
                    return None
                cur.execute("UPDATE api_keys SET last_used_at = %s WHERE key_id = %s", (now, row["key_id"]))
            conn.commit()
        return AccessContext(key_id=row["key_id"], tenant_id=row["tenant_id"], role=row["role"])

    def list_api_keys(self, tenant_id: str) -> list[ApiKeyRecord]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM api_keys WHERE tenant_id = %s ORDER BY created_at DESC", (tenant_id,))
                rows = cur.fetchall()
        return [_row_to_api_key(row) for row in rows]

    def revoke_api_key(self, tenant_id: str, key_id: str) -> ApiKeyRecord | None:
        revoked_at = _utc_now()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE api_keys SET revoked_at = %s WHERE tenant_id = %s AND key_id = %s AND revoked_at IS NULL",
                    (revoked_at, tenant_id, key_id),
                )
                cur.execute("SELECT * FROM api_keys WHERE tenant_id = %s AND key_id = %s", (tenant_id, key_id))
                row = cur.fetchone()
            conn.commit()
        return _row_to_api_key(row) if row else None

    def create_agent(self, tenant_id: str, agent_id: str, registration: AgentRegistration) -> AgentRecord:
        created_at = _utc_now()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO agents (agent_id, tenant_id, name, owner, description, allowed_domains, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (agent_id, tenant_id, registration.name, registration.owner, registration.description, json.dumps(registration.allowed_domains), created_at),
                )
            conn.commit()
        return AgentRecord(agent_id=agent_id, tenant_id=tenant_id, created_at=created_at, **registration.model_dump())

    def get_agent(self, tenant_id: str, agent_id: str) -> AgentRecord | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM agents WHERE tenant_id = %s AND agent_id = %s", (tenant_id, agent_id))
                row = cur.fetchone()
        return _row_to_agent(row) if row else None

    def list_agents(self, tenant_id: str) -> list[AgentRecord]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM agents WHERE tenant_id = %s ORDER BY created_at DESC", (tenant_id,))
                rows = cur.fetchall()
        return [_row_to_agent(row) for row in rows]

    def create_event(self, tenant_id: str, agent_id: str, action: str, decision: str, anomaly: bool, proof: str, findings: list[dict], context: dict, source_url: str | None) -> EventRecord:
        created_at = _utc_now()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO events (tenant_id, agent_id, action, decision, anomaly, proof, findings, context, source_url, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s) RETURNING id",
                    (tenant_id, agent_id, action, decision, anomaly, proof, json.dumps(findings), json.dumps(context), source_url, created_at),
                )
                event_id = cur.fetchone()["id"]
            conn.commit()
        return EventRecord(id=event_id, tenant_id=tenant_id, agent_id=agent_id, action=action, decision=decision, anomaly=anomaly, proof=proof, findings=findings, context=context, source_url=source_url, created_at=created_at)

    def list_events(self, tenant_id: str, limit: int = 50, decision: str | None = None) -> list[EventRecord]:
        query = "SELECT * FROM events WHERE tenant_id = %s"
        params: list[Any] = [tenant_id]
        if decision:
            query += " AND decision = %s"
            params.append(decision)
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        return [_row_to_event(row) for row in rows]

    def verify_proof(self, tenant_id: str, proof: str) -> bool:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM events WHERE tenant_id = %s AND proof = %s", (tenant_id, proof))
                row = cur.fetchone()
        return bool(row)

    def alert_summary(self, tenant_id: str) -> AlertSummary:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) AS total_events,
                           SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END) AS blocked_events,
                           SUM(CASE WHEN decision = 'review' THEN 1 ELSE 0 END) AS review_events,
                           SUM(CASE WHEN anomaly = TRUE THEN 1 ELSE 0 END) AS anomalous_events
                    FROM events WHERE tenant_id = %s
                    """,
                    (tenant_id,),
                )
                totals = cur.fetchone()
                cur.execute("SELECT findings FROM events WHERE tenant_id = %s", (tenant_id,))
                rows = cur.fetchall()
        parsed = [row["findings"] if isinstance(row["findings"], list) else json.loads(row["findings"]) for row in rows]
        return _build_alert_summary(totals, parsed)

    def tenant_overviews(self) -> list[TenantOverview]:
        overviews: list[TenantOverview] = []
        for tenant in self.list_tenants():
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS count FROM agents WHERE tenant_id = %s", (tenant.tenant_id,))
                    agent_count = cur.fetchone()["count"]
            overviews.append(TenantOverview(tenant=tenant, agent_count=agent_count, alert_summary=self.alert_summary(tenant.tenant_id)))
        return overviews


def create_store(database_path: str, database_url: str | None = None):
    return PostgresStore(database_url) if database_url else SQLiteStore(database_path)


def _row_to_event(row: dict[str, Any]) -> EventRecord:
    findings = row["findings"] if isinstance(row["findings"], list) else json.loads(row["findings"])
    context = row["context"] if isinstance(row["context"], dict) else json.loads(row["context"])
    return EventRecord(id=row["id"], tenant_id=row["tenant_id"], agent_id=row["agent_id"], action=row["action"], decision=row["decision"], anomaly=bool(row["anomaly"]), proof=row["proof"], findings=findings, context=context, source_url=row["source_url"], created_at=_to_datetime(row["created_at"]))


def _row_to_tenant(row: dict[str, Any]) -> TenantRecord:
    return TenantRecord(tenant_id=row["tenant_id"], name=row["name"], slug=row["slug"], contact_email=row["contact_email"], plan=row["plan"], created_at=_to_datetime(row["created_at"]))


def _row_to_api_key(row: dict[str, Any]) -> ApiKeyRecord:
    revoked_at = _to_datetime(row["revoked_at"]) if row["revoked_at"] else None
    return ApiKeyRecord(key_id=row["key_id"], tenant_id=row["tenant_id"], name=row["name"], role=row["role"], created_at=_to_datetime(row["created_at"]), last_used_at=_to_datetime(row["last_used_at"]) if row["last_used_at"] else None, revoked_at=revoked_at, is_active=revoked_at is None)


def _row_to_agent(row: dict[str, Any]) -> AgentRecord:
    allowed = row["allowed_domains"] if isinstance(row["allowed_domains"], list) else json.loads(row["allowed_domains"])
    return AgentRecord(agent_id=row["agent_id"], tenant_id=row["tenant_id"], name=row["name"], owner=row["owner"], description=row["description"], allowed_domains=allowed, created_at=_to_datetime(row["created_at"]))


def _build_alert_summary(totals: dict[str, Any], findings_rows: list[list[dict[str, Any]]]) -> AlertSummary:
    counts: dict[str, int] = {}
    for findings in findings_rows:
        for finding in findings:
            code = finding["code"]
            counts[code] = counts.get(code, 0) + 1
    top_findings = [{"code": code, "count": count} for code, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:5]]
    return AlertSummary(total_events=totals["total_events"] or 0, blocked_events=totals["blocked_events"] or 0, review_events=totals["review_events"] or 0, anomalous_events=totals["anomalous_events"] or 0, top_findings=top_findings)


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
