from __future__ import annotations

import uuid
from pathlib import Path

from ai_guardian.config import Settings
from ai_guardian.main import _render_dashboard, create_app
from ai_guardian.models import AgentRegistration, MonitorRequest, TenantCreate
from ai_guardian.notifications import AlertDispatcher
from ai_guardian.security import stable_hash
from ai_guardian.service import GuardianService


def make_db_path() -> str:
    db_dir = Path(".test-data")
    db_dir.mkdir(exist_ok=True)
    return str(db_dir / f"{uuid.uuid4().hex}.db")


def make_service():
    settings = Settings(
        service_name="AI Guardian Test",
        bootstrap_api_keys=("bootstrap-key",),
        database_path=make_db_path(),
        blocked_domains=("pastebin.com",),
        default_allowed_domains=("github.com", "example.com"),
        suspicious_phrases=("ignore previous instructions", "disable guard"),
        webhook_urls=(),
        rate_limit_per_minute=120,
        database_url=None,
    )
    return GuardianService(settings)


def bootstrap(service: GuardianService):
    return service.bootstrap_tenant(
        TenantCreate(
            name="Armpit Symphony",
            slug=f"armpit-symphony-{uuid.uuid4().hex[:6]}",
            contact_email="ops@myproduct.com",
            plan="growth",
        )
    )


def register_agent(service: GuardianService):
    bootstrap_result = bootstrap(service)
    access = service.authenticate(bootstrap_result.api_key)
    assert access is not None
    record = service.register_agent(
        access,
        AgentRegistration(
            name="site-defender",
            owner="armpit-symphony",
            description="Protects production bots and website workflows.",
            allowed_domains=["github.com", "myproduct.com"],
        ),
    )
    return record.agent_id, access


def test_app_factory_builds():
    settings = Settings(
        service_name="AI Guardian Test",
        bootstrap_api_keys=("bootstrap-key",),
        database_path=make_db_path(),
        blocked_domains=("pastebin.com",),
        default_allowed_domains=("github.com",),
        suspicious_phrases=("ignore previous instructions",),
        webhook_urls=(),
        rate_limit_per_minute=120,
        database_url=None,
    )
    app = create_app(settings)
    assert app.title == "AI Guardian Test"


def test_blocks_secret_leak_and_verifies_proof():
    service = make_service()
    agent_id, access = register_agent(service)

    result = service.monitor(
        access,
        MonitorRequest(
            agent_id=agent_id,
            action="Send deployment logs",
            context={"message": "bearer super-secret-token-value-123456789"},
            source_url="https://github.com/armpit-symphony/Ai-Guardian",
            context_checksum=stable_hash({"message": "bearer super-secret-token-value-123456789"}),
        ),
    )
    assert result.decision == "block"
    assert any(item.code == "generic_bearer" for item in result.findings)
    assert service.verify_proof(access, result.proof) is True


def test_reviews_unknown_domain_and_blocked_domain():
    service = make_service()
    agent_id, access = register_agent(service)

    unknown = service.monitor(
        access,
        MonitorRequest(
            agent_id=agent_id,
            action="Read changelog",
            context={"task": "triage"},
            source_url="https://unknown-vendor.example/security",
        ),
    )
    assert unknown.decision == "review"

    blocked = service.monitor(
        access,
        MonitorRequest(
            agent_id=agent_id,
            action="Upload backup",
            context={"task": "sync"},
            source_url="https://pastebin.com/raw/12345",
        ),
    )
    assert blocked.decision == "block"


def test_detects_context_tamper_and_exposes_summary():
    service = make_service()
    agent_id, access = register_agent(service)

    result = service.monitor(
        access,
        MonitorRequest(
            agent_id=agent_id,
            action="Update homepage copy",
            context={"page": "landing", "approved": False},
            source_url="https://github.com/armpit-symphony/Ai-Guardian",
            context_checksum=stable_hash({"page": "landing", "approved": True}),
        ),
    )
    assert result.decision == "block"
    assert any(item.code == "context_tamper" for item in result.findings)

    summary = service.store.alert_summary(access.tenant_id)
    assert summary.total_events == 1
    assert summary.blocked_events == 1
    assert summary.anomalous_events == 1


def test_bootstraps_tenant_and_scopes_keys():
    service = make_service()
    bootstrap_result = bootstrap(service)
    access = service.authenticate(bootstrap_result.api_key)
    assert access is not None
    assert access.tenant_id == bootstrap_result.tenant.tenant_id
    assert access.role == "admin"

    issued_key, meta = service.create_api_key(access, name="CI ingest", role="ingest")
    ingest_access = service.authenticate(issued_key)
    assert ingest_access is not None
    assert ingest_access.role == "ingest"
    keys = service.list_api_keys(access)
    assert any(item.key_id == meta.key_id for item in keys)


def test_can_rotate_and_revoke_keys():
    service = make_service()
    bootstrap_result = bootstrap(service)
    access = service.authenticate(bootstrap_result.api_key)
    assert access is not None

    issued_key, meta = service.create_api_key(access, name="CI ingest", role="ingest")
    rotated_key, rotated_meta = service.rotate_api_key(access, meta.key_id)
    assert service.authenticate(issued_key) is None
    rotated_access = service.authenticate(rotated_key)
    assert rotated_access is not None
    assert rotated_meta.role == "ingest"

    revoked = service.revoke_api_key(access, rotated_meta.key_id)
    assert revoked is not None
    assert revoked.is_active is False
    assert service.authenticate(rotated_key) is None


def test_dispatches_webhook_for_blocked_events():
    service = make_service()
    sent: list[tuple[str, dict]] = []
    service.alerts = AlertDispatcher(("https://hooks.example.test/guardian",), sender=lambda url, payload: sent.append((url, payload)))
    agent_id, access = register_agent(service)
    service.monitor(
        access,
        MonitorRequest(
            agent_id=agent_id,
            action="Upload backup",
            context={"task": "sync"},
            source_url="https://pastebin.com/raw/12345",
        ),
    )
    assert len(sent) == 1
    assert sent[0][1]["decision"] == "block"


def test_dashboard_data_includes_tenant_overview():
    service = make_service()
    agent_id, access = register_agent(service)
    service.monitor(
        access,
        MonitorRequest(
            agent_id=agent_id,
            action="Upload backup",
            context={"task": "sync"},
            source_url="https://pastebin.com/raw/12345",
        ),
    )
    html = _render_dashboard(service)
    assert "AI Guardian Ops" in html
    assert "Armpit Symphony" in html
    assert "Blocked" in html
