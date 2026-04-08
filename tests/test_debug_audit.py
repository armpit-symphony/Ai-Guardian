"""Debug test — ONE-SHOT debug of audit log emptiness."""
from __future__ import annotations

import uuid
from fastapi.testclient import TestClient
from ai_guardian.config import Settings
from ai_guardian.main import create_app


def test_debug_audit_log():
    """Find why audit entries aren't being written."""
    from ai_guardian import audit as am
    from ai_guardian import interceptor as im

    tmp = __import__("tempfile").NamedTemporaryFile(suffix=".db", delete=False)
    db_path = tmp.name
    tmp.close()

    settings = Settings(
        service_name="AI Guardian Debug",
        bootstrap_api_keys=("dev-guardian-key",),
        database_url=None,
        database_path=db_path,
        blocked_domains=(),
        default_allowed_domains=(),
        suspicious_phrases=(),
        webhook_urls=(),
        rate_limit_per_minute=120,
    )
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=True) as c:
        tenant_slug = f"ten-debug-{uuid.uuid4().hex[:8]}"
        r = c.post(
            "/api/v1/bootstrap/tenants",
            headers={"x-bootstrap-key": "dev-guardian-key"},
            json={
                "name": "Debug Tenant",
                "slug": tenant_slug,
                "contact_email": "debug@test.ai",
            },
        )
        assert r.status_code == 200, f"Bootstrap failed: {r.status_code} {r.text}"
        admin_key = r.json()["api_key"]
        tenant_id = r.json()["tenant"]["tenant_id"]

        print(f"\n[DEBUG] tenant_id={tenant_id}")
        print(f"[DEBUG] audit_log id={id(am.audit_log)}")
        print(f"[DEBUG] im.audit_log id={id(im.audit_log)}")
        print(f"[DEBUG] audit entries before monitor: {list(am.audit_log._entries.keys())}")

        # Submit read_logs
        r = c.post(
            "/api/v1/monitor",
            headers={"x-api-key": admin_key},
            json={"agent_id": "agt_debug", "action": "read_logs", "context": {}},
        )
        print(f"[DEBUG] monitor response: {r.status_code} {r.json()}")

        # Check audit entries
        tenant_entries = am.audit_log._entries.get(tenant_id, [])
        print(f"[DEBUG] audit entries after monitor: {len(tenant_entries)}")
        for e in tenant_entries:
            print(f"  entry: action={e['action']} decision={e['decision']}")

        # Also check via HTTP
        r = c.get("/api/v1/audit/logs", headers={"x-api-key": admin_key})
        print(f"[DEBUG] GET /audit/logs: {r.status_code} {r.json()}")

        # Manually append to verify audit log works
        am.audit_log.append(
            tenant_id=tenant_id,
            actor="test",
            action="manual_test",
            decision="blocked",
        )
        tenant_entries = am.audit_log._entries.get(tenant_id, [])
        print(f"[DEBUG] after manual append: {len(tenant_entries)} entries")
        for e in tenant_entries:
            print(f"  entry: action={e['action']} decision={e['decision']}")

    import os
    os.unlink(db_path)
