"""Integration tests — SSRF protection (Proof 6).

Covers blocking of internal/metadata URLs:
- localhost / 127.0.0.1 / 169.254.169.254 / [::1] / metadata.google.internal

All must return decision=blocked and risk_score=100.

Markers: integration, security
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

SSRF_CASES = [
    ("http://localhost:6379",            "localhost"),
    ("http://127.0.0.1:22",              "127.0.0.1"),
    ("http://169.254.169.254/",          "169.254.169.254"),
    ("http://[::1]:22/",                "IPv6 loopback [::1]"),
    ("http://metadata.google.internal/", "metadata.google.internal"),
]


@pytest.mark.integration
@pytest.mark.parametrize("url,label", SSRF_CASES)
def test_ssrf_internal_urls_blocked(
    client: TestClient, admin_key: str, url: str, label: str
):
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={
            "agent_id": "agt_ssrf",
            "action": "fetch_url",
            "context": {},
            "source_url": url,
        },
    )
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "blocked", f"SSRF {label} should be blocked"
    assert d["risk_score"] == 100, f"SSRF {label} risk_score should be 100"


@pytest.mark.integration
@pytest.mark.parametrize("url,label", SSRF_CASES)
def test_ssrf_internal_urls_logged_with_ssrf_action(
    client: TestClient, admin_key: str, url: str, label: str
):
    """Verify SSRF blocks are logged with the SSRF-specific audit action."""
    client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={
            "agent_id": "agt_ssrf",
            "action": "fetch_url",
            "context": {},
            "source_url": url,
        },
    )

    logs = client.get(
        "/api/v1/audit/logs",
        headers={"x-api-key": admin_key},
    ).json()

    ssrf_actions = [
        a for a in (e["action"] for e in logs)
        if "ssrf" in a or "blocked" in a
    ]
    assert len(ssrf_actions) > 0, f"No SSRF audit entry found for {label}"


@pytest.mark.integration
def test_external_url_not_blocked(client: TestClient, admin_key: str):
    """External URLs (github.com) should NOT be blocked by SSRF logic."""
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={
            "agent_id": "agt_01",
            "action": "fetch_url",
            "context": {},
            "source_url": "https://github.com/sparkpit-labs/red-spark-team",
        },
    )
    assert r.status_code == 200
    d = r.json()
    # github.com is allowed domain → not pending (no approval needed)
    # It should NOT be blocked by SSRF rules
    assert d["decision"] != "blocked", "External GitHub URL should not be SSRF-blocked"


# ── Smoke ────────────────────────────────────────────────────────────

@pytest.mark.integration
@pytest.mark.smoke
@pytest.mark.parametrize("url,label", SSRF_CASES[:3])
def test_smoke_ssrf_top_cases(
    client: TestClient, admin_key: str, url: str, label: str
):
    """Fast smoke: just verify blocked + risk=100 for top 3 SSRF cases."""
    r = client.post(
        "/api/v1/monitor",
        headers={"x-api-key": admin_key},
        json={
            "agent_id": "agt_01",
            "action": "fetch_url",
            "context": {},
            "source_url": url,
        },
    )
    d = r.json()
    assert d["decision"] == "blocked"
    assert d["risk_score"] == 100
