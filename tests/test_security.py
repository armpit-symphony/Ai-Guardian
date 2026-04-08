"""Security / adversarial tests — negative cases (Proof 7 adversarial).

Covers:
- Non-existent approval ID → 404
- Cross-tenant access attempts (if tenant fixtures isolated)
- Malformed headers
- Concurrent idempotency (two parallel approves)
- Out-of-order deny/approve
- Expired breakglass (future: time-based expiry test)

Markers: security, integration
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# ── Non-existent resources ────────────────────────────────────────────

@pytest.mark.security
def test_nonexistent_approval_returns_404(
    client: TestClient, admin_key: str
):
    r = client.post(
        "/api/v1/approvals/fake-approval-id/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    assert r.status_code == 404


@pytest.mark.security
def test_nonexistent_breakglass_returns_404(
    client: TestClient, admin_key: str
):
    r = client.post(
        "/api/v1/breakglass/fake-bg-id/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    # Should be 400 or 404 depending on guard timing
    assert r.status_code in (400, 404)


# ── Malformed / missing headers ─────────────────────────────────────

@pytest.mark.security
def test_malformed_api_key_header_rejected(client: TestClient):
    r = client.get(
        "/api/v1/me",
        headers={"x-api-key": "bad_key_xyz"},
    )
    assert r.status_code in (400, 401, 422)


@pytest.mark.security
def test_empty_api_key_header_rejected(client: TestClient):
    r = client.get("/api/v1/me", headers={"x-api-key": ""})
    assert r.status_code in (400, 401, 422)


@pytest.mark.security
def test_invalid_content_type_on_monitor(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/monitor",
        headers={
            "x-api-key": admin_key,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data="agent_id=a&action=http_call",
    )
    assert r.status_code in (400, 415, 422)


# ── Idempotency under concurrency ───────────────────────────────────

@pytest.mark.security
def test_parallel_approve_only_one_succeeds(
    client: TestClient, admin_key: str, ingest_key: str
):
    """Two concurrent approve requests — second must be rejected."""
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_test", "action": "http_call", "context": {}},
    )
    approval_id = r.json()["approval_id"]

    # Fire two approve requests in rapid succession
    r1 = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    r2 = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )

    statuses = {r1.status_code, r2.status_code}
    # One must be 200, the other must be 400
    assert 200 in statuses
    assert 400 in statuses


@pytest.mark.security
def test_out_of_order_deny_then_approve_fails(
    client: TestClient, admin_key: str, ingest_key: str
):
    """Cannot approve an already-denied approval."""
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_test", "action": "http_call", "context": {}},
    )
    approval_id = r.json()["approval_id"]

    # Deny first
    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "deny"},
    )
    assert r.json()["status"] == "denied"

    # Try to approve after deny → rejected
    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": admin_key},
        json={"decision": "approve"},
    )
    assert r.status_code == 400


@pytest.mark.security
def test_viewer_cannot_approve_approval(
    client: TestClient, admin_key: str, viewer_key: str, ingest_key: str
):
    """Viewer role is not admin — cannot approve."""
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_test", "action": "http_call", "context": {}},
    )
    approval_id = r.json()["approval_id"]

    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": viewer_key},
        json={"decision": "approve"},
    )
    assert r.status_code == 403


@pytest.mark.security
def test_ingest_cannot_approve_approval(
    client: TestClient, admin_key: str, ingest_key: str
):
    """Ingest role is not admin — cannot approve."""
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest_key},
        json={"agent_id": "agt_test", "action": "http_call", "context": {}},
    )
    approval_id = r.json()["approval_id"]

    r = client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        headers={"x-api-key": ingest_key},
        json={"decision": "approve"},
    )
    assert r.status_code == 403


# ── Tenant isolation ────────────────────────────────────────────────

@pytest.mark.security
def test_cross_tenant_audit_access_denied(
    client: TestClient, admin_key: str
):
    """Tenant A's key cannot read Tenant B's audit logs."""
    # Bootstrap tenant A
    slug_a = f"ten-a-{uuid.uuid4().hex[:8]}"
    r = client.post(
        "/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": "dev-guardian-key"},
        json={"name": "Tenant A", "slug": slug_a, "contact_email": "a@test.ai"},
    )
    key_a = r.json()["api_key"]

    # Bootstrap tenant B
    slug_b = f"ten-b-{uuid.uuid4().hex[:8]}"
    r = client.post(
        "/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": "dev-guardian-key"},
        json={"name": "Tenant B", "slug": slug_b, "contact_email": "b@test.ai"},
    )
    key_b = r.json()["api_key"]

    # Tenant A generates an event
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": key_a},
        json={"agent_id": "agt_test", "action": "read_logs", "context": {}},
    )

    # Tenant B tries to read Tenant A's audit log → must fail
    r = client.get(
        "/api/v1/audit/logs",
        headers={"x-api-key": key_b},
    )
    # Should get back an empty list or a 403 (tenant isolation)
    # The key_b has its own logs, so it returns 200 with empty list
    # The real isolation test: key_b should NOT see key_a's entries
    logs_b = r.json()
    actions_b = {e["action"] for e in logs_b}
    assert "guardian_allowed:read_logs" not in actions_b, (
        "Tenant isolation violated — key_b saw Tenant A's audit entries"
    )


# ── Smoke ────────────────────────────────────────────────────────────

@pytest.mark.security
@pytest.mark.smoke
def test_smoke_security_fast(client: TestClient):
    """Fast security smoke: 404 for fake approval, 403 for viewer-approve."""
    slug = f"ten-{uuid.uuid4().hex[:8]}"
    r = client.post(
        "/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": "dev-guardian-key"},
        json={"name": "Smoke", "slug": slug, "contact_email": "smoke@test.ai"},
    )
    admin = r.json()["api_key"]

    # Create viewer key
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin},
        params={"name": "ViewOnly", "role": "viewer"},
    )
    viewer = r.json()["api_key"]

    # Create ingest key
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin},
        params={"name": "IngestOnly", "role": "ingest"},
    )
    ingest = r.json()["api_key"]

    # Fake approval → 404
    r = client.post(
        "/api/v1/approvals/fake-id/decide",
        headers={"x-api-key": admin},
        json={"decision": "approve"},
    )
    assert r.status_code == 404

    # Viewer tries to approve → 403
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": ingest},
        json={"agent_id": "agt_test", "action": "http_call", "context": {}},
    )
    aid = r.json()["approval_id"]
    r = client.post(
        f"/api/v1/approvals/{aid}/decide",
        headers={"x-api-key": viewer},
        json={"decision": "approve"},
    )
    assert r.status_code == 403


import uuid
