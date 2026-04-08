"""Integration tests — Audit system (Proofs 5, 7).

Covers:
- All 6 decision types appear in audit log after forcing events
- Exact action taxonomy (frozen):
    guardian_allowed:{action}
    guardian_pending:{action}
    guardian_approval_approved:{action}
    guardian_approval_denied:{action}
    guardian_blocked_critical:{action}
    guardian_blocked:ssrf:{action}
    breakglass_create
    breakglass_override:{action}
    breakglass_revoke
- Audit hash chain valid
- Audit verify returns valid=True, errors=[]

Markers: integration, security
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


ALLOWED_DECISIONS = frozenset([
    "allowed",
    "blocked",
    "pending_approval",
    "approve",
    "deny",
    "breakglass_used",
])


@pytest.mark.integration
def test_audit_contains_all_six_decision_types(
    client: TestClient, admin_key: str, ingest_key: str
):
    """Force one event of each type, verify all 6 decisions appear."""
    # 1. allowed: read_logs (admin → allowed)
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "read_logs", "context": {}},
    )
    # 2. blocked: exec_code (admin → blocked by critical list)
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "exec_code", "context": {}},
    )
    # 3. pending_approval: http_call (ingest → pending_approval)
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_test", "action": "http_call", "context": {}},
    )
    # 4. approve: send_webhook via ingest → pending → admin approves
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_test", "action": "send_webhook", "context": {}},
    )
    aid = r.json()["approval_id"]
    client.post(
        f"/api/v1/approvals/{aid}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    # 5. deny: http_call via ingest → admin denies
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_test", "action": "http_call", "context": {}},
    )
    aid2 = r.json()["approval_id"]
    client.post(
        f"/api/v1/approvals/{aid2}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )
    # 6. breakglass_used: breakglass create/use
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": "audit completeness check session here",
            "duration_minutes": 5,
            "pin": "ai-guardian-breakglass-2026",
        },
    )
    bg_id = r.json()["breakglass_id"]
    client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )

    logs = client.get(
        "/api/v1/audit/logs",
        headers={"x-api-key": admin_key},
    ).json()
    decisions = {e["decision"] for e in logs}

    missing = ALLOWED_DECISIONS - decisions
    assert not missing, f"Audit missing decisions: {missing}"


@pytest.mark.integration
def test_audit_contains_required_action_patterns(
    client: TestClient, admin_key: str
):
    """Verify guardian action patterns appear for specific operations."""
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "read_logs", "context": {}},
    )
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "exec_code", "context": {}},
    )
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "delete_all_files", "context": {}},
    )

    logs = client.get(
        "/api/v1/audit/logs",
        headers={"x-api-key": admin_key},
    ).json()
    actions = {e["action"] for e in logs}

    assert "guardian_allowed:read_logs" in actions
    assert "guardian_blocked_critical:exec_code" in actions
    assert "guardian_blocked_critical:delete_all_files" in actions


@pytest.mark.integration
def test_breakglass_actions_in_audit(
    client: TestClient, admin_key: str
):
    """breakglass_create, breakglass_override, breakglass_revoke all logged."""
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": "breakglass audit verification session test",
            "duration_minutes": 5,
            "pin": "ai-guardian-breakglass-2026",
        },
    )
    bg_id = r.json()["breakglass_id"]

    client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )

    client.post(
        f"/api/v1/breakglass/{bg_id}/revoke",
        headers={"x-api-key": admin_key},
    )

    logs = client.get(
        "/api/v1/audit/logs",
        headers={"x-api-key": admin_key},
    ).json()
    actions = {e["action"] for e in logs}

    assert "breakglass_create" in actions
    assert "breakglass_override:delete_all_files" in actions
    assert "breakglass_revoke" in actions


@pytest.mark.integration
def test_audit_verify_hash_chain_valid(client: TestClient, admin_key: str):
    """GET /audit/verify returns valid=True and errors=[]."""
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "read_logs", "context": {}},
    )

    r = client.get(
        "/api/v1/audit/verify",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code == 200
    d = r.json()
    assert d["valid"] is True
    assert d["errors"] == []


@pytest.mark.integration
@pytest.mark.smoke
def test_smoke_audit_taxonomy(client: TestClient, admin_key: str):
    """Quick check: read_logs → allowed, exec_code → blocked."""
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "read_logs", "context": {}},
    )
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={"agent_id": "agt_test", "action": "exec_code", "context": {}},
    )

    logs = client.get(
        "/api/v1/audit/logs",
        headers={"x-api-key": admin_key},
    ).json()
    decisions = {e["decision"] for e in logs}

    assert "allowed" in decisions
    assert "blocked" in decisions
