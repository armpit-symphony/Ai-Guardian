"""Tests for WO-2026-0408-11: Operator hardening features."""
import pytest


def test_blocked_filter_on_audit_logs(client, admin_key):
    """?decision=blocked filters audit logs to only blocked entries."""
    # Submit an action that will be blocked (delete_all_files)
    r = client.post("/api/v1/monitor", headers={"x-api-key": admin_key},
                    json={"agent_id": "agt_test", "action": "delete_all_files", "context": {}})
    assert r.status_code == 200
    assert r.json()["decision"] == "blocked"

    # Submit an action that will be allowed
    r2 = client.post("/api/v1/monitor", headers={"x-api-key": admin_key},
                     json={"agent_id": "agt_test", "action": "read_data", "context": {}})
    assert r2.status_code == 200

    # Filter by blocked
    r3 = client.get("/api/v1/audit/logs?decision=blocked", headers={"x-api-key": admin_key})
    assert r3.status_code == 200
    entries = r3.json()
    assert all(e["decision"] == "blocked" for e in entries), "All entries should be blocked"


def test_blocked_endpoint(client, admin_key):
    """GET /api/v1/audit/blocked returns only blocked entries."""
    # Clear: submit blocked action first
    r = client.post("/api/v1/monitor", headers={"x-api-key": admin_key},
                    json={"agent_id": "agt_test", "action": "delete_all_files", "context": {}})
    assert r.json()["decision"] == "blocked"

    r2 = client.get("/api/v1/audit/blocked", headers={"x-api-key": admin_key})
    assert r2.status_code == 200
    entries = r2.json()
    assert all(e["decision"] == "blocked" for e in entries)


def test_breakglass_use_requires_confirmation(client, admin_key):
    """Breakglass use without confirmation field is rejected."""
    # Create breakglass first
    r = client.post("/api/v1/breakglass", headers={"x-api-key": admin_key},
                     json={"reason": "Confirmation test session for validation", "pin": "ai-guardian-breakglass-2026"})
    assert r.status_code == 200
    bg_id = r.json()["breakglass_id"]

    # Try use WITHOUT confirm field → should fail with 400 (bad request semantics)
    r2 = client.post(f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
                      headers={"x-api-key": admin_key},
                      json={"action": "delete_all_files"})
    assert r2.status_code == 400, "Missing confirm should return 400 Bad Request"


def test_breakglass_use_with_confirmation(client, admin_key):
    """Breakglass use WITH correct confirmation works."""
    r = client.post("/api/v1/breakglass", headers={"x-api-key": admin_key},
                     json={"reason": "Confirm test for breakglass use endpoint", "pin": "ai-guardian-breakglass-2026"})
    assert r.status_code == 200
    bg_id = r.json()["breakglass_id"]

    # Use WITH confirmation
    r2 = client.post(f"/api/v1/breakglass/{bg_id}/use",
                      headers={"x-api-key": admin_key},
                      json={"action": "delete_all_files", "confirm": "BREAKGLASS"})
    assert r2.status_code == 200, f"Confirmation should succeed: {r2.json()}"


def test_breakglass_use_wrong_confirmation(client, admin_key):
    """Breakglass use with wrong confirmation value is rejected."""
    r = client.post("/api/v1/breakglass", headers={"x-api-key": admin_key},
                     json={"reason": "Wrong confirm value test session", "pin": "ai-guardian-breakglass-2026"})
    assert r.status_code == 200
    bg_id = r.json()["breakglass_id"]

    r2 = client.post(f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files&confirm=WRONG",
                      headers={"x-api-key": admin_key})
    assert r2.status_code == 400, "Wrong confirm value should return 400"


def test_status_endpoint(client, admin_key):
    """GET /api/v1/status returns operational status."""
    r = client.get("/api/v1/status", headers={"x-api-key": admin_key})
    assert r.status_code == 200
    d = r.json()
    assert "pending_approvals" in d
    assert "blocked_today" in d
    assert "breakglass_active" in d
    assert "audit_integrity_valid" in d
    assert "audit_errors" in d
    assert "active_breakglass_sessions" in d
    # audit_integrity_valid should be True (chain intact)
    assert d["audit_integrity_valid"] is True


def test_status_endpoint_requires_admin(client, viewer_key):
    """Status endpoint is admin-only."""
    r = client.get("/api/v1/status", headers={"x-api-key": viewer_key})
    assert r.status_code == 403
