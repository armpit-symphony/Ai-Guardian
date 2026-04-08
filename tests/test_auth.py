"""Integration tests — Authentication path (Proof 1).

Covers:
- Bootstrap tenant
- Key creation (admin, ingest, viewer)
- /me returns correct api_key.role
- Invalid key → 401
- Missing key → 422

Markers: integration, security
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient


# ── Bootstrap ────────────────────────────────────────────────────────

@pytest.mark.integration
def test_bootstrap_creates_tenant_and_admin_key(client: TestClient):
    r = client.post(
        "/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": "dev-guardian-key"},
        json={
            "name": "Test Tenant",
            "slug": f"ten-{uuid.uuid4().hex[:8]}",
            "contact_email": "test@test.ai",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "api_key" in data
    assert data["api_key"].startswith("aig_live_")


@pytest.mark.integration
def test_bootstrap_rejects_invalid_bootstrap_key(client: TestClient):
    r = client.post(
        "/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": "wrong-key"},
        json={
            "name": "Bad",
            "slug": "bad",
            "contact_email": "bad@test.ai",
        },
    )
    assert r.status_code in (401, 403)


# ── Key creation ─────────────────────────────────────────────────────

@pytest.mark.integration
def test_create_ingest_key(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin_key},
        params={"name": "IngestWorker", "role": "ingest"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["api_key"].startswith("aig_live_")
    assert data["key_meta"]["name"] == "IngestWorker"
    assert data["key_meta"]["role"] == "ingest"


@pytest.mark.integration
def test_create_viewer_key(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin_key},
        params={"name": "ViewerWorker", "role": "viewer"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["api_key"].startswith("aig_live_")
    assert data["key_meta"]["name"] == "ViewerWorker"
    assert data["key_meta"]["role"] == "viewer"


@pytest.mark.integration
def test_create_key_rejects_short_name(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin_key},
        params={"name": "V", "role": "viewer"},
    )
    assert r.status_code == 422


@pytest.mark.integration
def test_create_key_rejects_invalid_role(client: TestClient, admin_key: str):
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin_key},
        params={"name": "BadRole", "role": "operator"},
    )
    assert r.status_code in (400, 422)


# ── /me endpoint ────────────────────────────────────────────────────

@pytest.mark.integration
def test_me_returns_api_key_role_ingest(client: TestClient, ingest_key: str):
    r = client.get("/api/v1/me", headers={"x-api-key": ingest_key})
    assert r.status_code == 200
    data = r.json()
    assert data["api_key"]["role"] == "ingest"


@pytest.mark.integration
def test_me_returns_api_key_role_viewer(client: TestClient, viewer_key: str):
    r = client.get("/api/v1/me", headers={"x-api-key": viewer_key})
    assert r.status_code == 200
    data = r.json()
    assert data["api_key"]["role"] == "viewer"


@pytest.mark.integration
def test_me_rejects_invalid_key(client: TestClient):
    r = client.get("/api/v1/me", headers={"x-api-key": "bad_key_xyz"})
    assert r.status_code == 401


@pytest.mark.integration
def test_me_rejects_missing_key(client: TestClient):
    r = client.get("/api/v1/me")
    assert r.status_code == 422


# ── Smoke ────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.smoke
def test_smoke_auth_path(client: TestClient):
    """Bootstrap → create ingest key → /me → correct role. Quick sanity."""
    slug = f"ten-{uuid.uuid4().hex[:8]}"
    r = client.post(
        "/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": "dev-guardian-key"},
        json={"name": "Smoke", "slug": slug, "contact_email": "smoke@test.ai"},
    )
    admin = r.json()["api_key"]
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin},
        params={"name": "SmokeIngest", "role": "ingest"},
    )
    ingest = r.json()["api_key"]
    r = client.get("/api/v1/me", headers={"x-api-key": ingest})
    assert r.status_code == 200
    assert r.json()["api_key"]["role"] == "ingest"
