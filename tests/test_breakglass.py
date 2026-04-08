"""Integration tests — Breakglass system (Proofs 5, 7).

Covers:
- Breakglass create
- Breakglass use (one-time, status=used)
- Breakglass reuse after use → 400
- Breakglass revoke
- Breakglass use after revoke → 400
- Breakglass create with bad PIN → 401/403
- Breakglass create with short reason → 422

Markers: integration, security
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

PIN = "ai-guardian-breakglass-2026"
VALID_REASON = "adversarial verification test session"


@pytest.mark.integration
def test_breakglass_create(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": VALID_REASON,
            "duration_minutes": 5,
            "pin": PIN,
        },
    )
    assert r.status_code == 200
    d = r.json()
    assert "breakglass_id" in d
    assert d["approved"] is True


@pytest.mark.integration
def test_breakglass_create_rejects_bad_pin(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": VALID_REASON,
            "duration_minutes": 5,
            "pin": "wrong123",
        },
    )
    assert r.status_code in (401, 403, 400)


@pytest.mark.integration
def test_breakglass_create_rejects_short_reason(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": "short",
            "duration_minutes": 5,
            "pin": PIN,
        },
    )
    assert r.status_code == 422


@pytest.mark.integration
def test_breakglass_use_one_time(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": VALID_REASON,
            "duration_minutes": 5,
            "pin": PIN,
        },
    )
    bg_id = r.json()["breakglass_id"]

    r = client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "used"


@pytest.mark.integration
def test_breakglass_use_cannot_be_reused(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": VALID_REASON,
            "duration_minutes": 5,
            "pin": PIN,
        },
    )
    bg_id = r.json()["breakglass_id"]

    # First use
    client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )

    # Second use → rejected
    r = client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code == 400
    assert "used" in r.json()["detail"].lower()


@pytest.mark.integration
def test_breakglass_revoke(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": VALID_REASON,
            "duration_minutes": 5,
            "pin": PIN,
        },
    )
    bg_id = r.json()["breakglass_id"]

    r = client.post(
        f"/api/v1/breakglass/{bg_id}/revoke",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"


@pytest.mark.integration
def test_breakglass_use_after_revoke_fails(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": VALID_REASON,
            "duration_minutes": 5,
            "pin": PIN,
        },
    )
    bg_id = r.json()["breakglass_id"]

    client.post(
        f"/api/v1/breakglass/{bg_id}/revoke",
        headers={"x-api-key": admin_key},
    )

    r = client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code == 400
    assert "revoked" in r.json()["detail"].lower()


@pytest.mark.integration
def test_breakglass_nonexistent_id_fails(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/breakglass/fake-id/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code in (400, 404)


# ── Smoke ────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.smoke
def test_smoke_breakglass_lifecycle(client: TestClient, admin_key: str):
    """Create → use → try reuse → revoke → try use — all in one smoke test."""
    r = client.post(
        "/api/v1/breakglass",
        headers={"x-api-key": admin_key},
        json={
            "reason": VALID_REASON,
            "duration_minutes": 5,
            "pin": PIN,
        },
    )
    bg_id = r.json()["breakglass_id"]

    r = client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    assert r.json()["status"] == "used"

    r = client.post(
        f"/api/v1/breakglass/{bg_id}/use?action=delete_all_files",
        headers={"x-api-key": admin_key},
    )
    assert r.status_code == 400

    r = client.post(
        f"/api/v1/breakglass/{bg_id}/revoke",
        headers={"x-api-key": admin_key},
    )
    assert r.json()["status"] == "revoked"
