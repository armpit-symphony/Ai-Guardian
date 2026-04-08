"""Pytest configuration and shared fixtures for Phase 7 tests.

Scope: each fixture creates an isolated temp-file DB per test function.
No shared state between tests.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from typing import TYPE_CHECKING, Generator

import pytest
from fastapi.testclient import TestClient

if TYPE_CHECKING:
    pass

from ai_guardian.config import Settings
from ai_guardian.main import create_app


# ── Test markers ──────────────────────────────────────────────────────
def pytest_configure(config):  # type: ignore[var-annotated]
    config.addinivalue_line("markers", "unit: Unit tests (no external I/O)")
    config.addinivalue_line("markers", "integration: Full-stack HTTP integration tests")
    config.addinivalue_line("markers", "security: Adversarial / security tests")
    config.addinivalue_line("markers", "smoke: Fast smoke tests for CI gate")


# ── App fixture ─────────────────────────────────────────────────────
@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """FastAPI TestClient with a fresh temp-file DB per test."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = tmp.name
    tmp.close()
    settings = Settings(
        service_name="AI Guardian Phase7 Test",
        bootstrap_api_keys=("dev-guardian-key",),
        database_url=None,
        database_path=db_path,
        blocked_domains=("localhost", "127.0.0.1", "169.254.169.254"),
        default_allowed_domains=("github.com",),
        suspicious_phrases=(),
        webhook_urls=(),
        rate_limit_per_minute=120,
    )
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    try:
        os.unlink(db_path)
    except OSError:
        pass


# ── Tenant bootstrap ─────────────────────────────────────────────────
@pytest.fixture(scope="function")
def bootstrap(client: TestClient) -> dict:
    """Bootstrap a fresh tenant. Returns {api_key, tenant_id}."""
    slug = f"ten-{uuid.uuid4().hex[:8]}"
    r = client.post(
        "/api/v1/bootstrap/tenants",
        headers={"x-bootstrap-key": "dev-guardian-key"},
        json={
            "name": "Phase7 Tenant",
            "slug": slug,
            "contact_email": "phase7@test.ai",
        },
    )
    assert r.status_code == 200, f"Bootstrap failed: {r.status_code} {r.text}"
    data = r.json()
    return {
        "api_key": data["api_key"],
        "tenant_id": data["tenant"]["tenant_id"],
    }


# ── Key fixtures ─────────────────────────────────────────────────────
@pytest.fixture(scope="function")
def admin_key(client: TestClient, bootstrap: dict) -> str:
    """Bootstrap admin key (from bootstrap fixture)."""
    return bootstrap["api_key"]


@pytest.fixture(scope="function")
def ingest_key(client: TestClient, admin_key: str) -> str:
    """Ingest-role API key."""
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin_key},
        params={"name": "IngestWorker", "role": "ingest"},
    )
    assert r.status_code == 200, f"ingest key creation failed: {r.status_code} {r.text}"
    return r.json()["api_key"]


@pytest.fixture(scope="function")
def viewer_key(client: TestClient, admin_key: str) -> str:
    """Viewer-role API key."""
    r = client.post(
        "/api/v1/api-keys",
        headers={"x-api-key": admin_key},
        params={"name": "ViewerWorker", "role": "viewer"},
    )
    assert r.status_code == 200, f"viewer key creation failed: {r.status_code} {r.text}"
    return r.json()["api_key"]


# ── Audit helpers ───────────────────────────────────────────────────
def get_audit_logs(client: TestClient, key: str) -> list[dict]:
    r = client.get("/api/v1/audit/logs", headers={"x-api-key": key})
    assert r.status_code == 200, f"audit log fetch failed: {r.status_code} {r.text}"
    return r.json()


def get_audit_decisions(client: TestClient, key: str) -> set[str]:
    return {e["decision"] for e in get_audit_logs(client, key)}


def get_audit_actions(client: TestClient, key: str) -> set[str]:
    return {e["action"] for e in get_audit_logs(client, key)}
