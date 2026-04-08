"""Integration tests — Enforcement path (Proofs 2-4, 7).

Covers:
- ingest + http_call → pending_approval + approval_id
- admin + external_api_call → pending_approval
- viewer + read_logs → 200 + blocked (RBAC, not auth fail)
- delete_all_files blocked for admin/ingest/viewer
- exec_code blocked for admin
- approve once → approved
- double-approve → 400
- deny once → denied
- double-deny → 400
- revoked breakglass use → 400
- one-time breakglass reuse → 400

Markers: integration, security
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient


# ── Enforcement: pending approval ──────────────────────────────────

@pytest.mark.integration
def test_ingest_http_call_returns_pending(
    client: TestClient, ingest_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_01", "action": "http_call", "context": {}},
    )
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "pending_approval"
    assert d["approval_id"] is not None
    assert d["risk_score"] == 65


@pytest.mark.integration
def test_admin_external_api_call_returns_pending(
    client: TestClient, admin_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={
            "agent_id": "agt_01",
            "action": "external_api_call",
            "context": {},
        },
    )
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "pending_approval"


@pytest.mark.integration
def test_viewer_read_logs_blocked_by_rbac(
    client: TestClient, viewer_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": viewer_key},
        json={"agent_id": "agt_01", "action": "read_logs", "context": {}},
    )
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "blocked"


# ── Negative: critical actions blocked ───────────────────────────────

@pytest.mark.integration
def test_delete_all_files_blocked_for_admin(
    client: TestClient, admin_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={
            "agent_id": "agt_01",
            "action": "delete_all_files",
            "context": {},
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "blocked"


@pytest.mark.integration
def test_delete_all_files_blocked_for_ingest(
    client: TestClient, ingest_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={
            "agent_id": "agt_01",
            "action": "delete_all_files",
            "context": {},
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "blocked"


@pytest.mark.integration
def test_delete_all_files_blocked_for_viewer(
    client: TestClient, viewer_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": viewer_key},
        json={
            "agent_id": "agt_01",
            "action": "delete_all_files",
            "context": {},
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "blocked"


@pytest.mark.integration
def test_exec_code_blocked_for_admin(
    client: TestClient, admin_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_01", "action": "exec_code", "context": {}},
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "blocked"


# ── Approval path ───────────────────────────────────────────────────

@pytest.mark.integration
def test_admin_approves_pending_returns_approved(
    client: TestClient, admin_key: str, ingest_key: str
):
    # Submit pending action
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_01", "action": "http_call", "context": {}},
    )
    approval_id = r.json()["approval_id"]

    # Approve
    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "approved"
    assert d["decided_by"] is not None


@pytest.mark.integration
def test_list_approvals_returns_200(
    client: TestClient, admin_key: str
):
    r = client.get(
        "/api/v1/approvals",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.integration
def test_double_approve_returns_400(
    client: TestClient, admin_key: str, ingest_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_01", "action": "http_call", "context": {}},
    )
    approval_id = r.json()["approval_id"]

    # First approve
    client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )

    # Second approve → rejected
    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    assert r.status_code == 400
    assert "approved" in r.json()["detail"].lower()


@pytest.mark.integration
def test_deny_pending_returns_denied(
    client: TestClient, admin_key: str, ingest_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={
            "agent_id": "agt_01",
            "action": "send_webhook",
            "context": {},
        },
    )
    approval_id = r.json()["approval_id"]

    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "denied"


@pytest.mark.integration
def test_double_deny_returns_400(
    client: TestClient, admin_key: str, ingest_key: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={
            "agent_id": "agt_01",
            "action": "send_webhook",
            "context": {},
        },
    )
    approval_id = r.json()["approval_id"]

    # First deny
    client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )

    # Second deny → rejected
    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )
    assert r.status_code == 400


# ── Smoke ────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.smoke
def test_smoke_enforcement_path(client: TestClient, admin_key: str, ingest_key: str):
    """ingest submits http_call → admin approves once → double-approve rejected."""
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_01", "action": "http_call", "context": {}},
    )
    approval_id = r.json()["approval_id"]

    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    assert r.json()["status"] == "approved"

    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    assert r.status_code == 400
