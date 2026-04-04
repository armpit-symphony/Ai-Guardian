from __future__ import annotations

from ai_guardian.agent_sim import MockAgent
from ai_guardian.config import Settings
from ai_guardian.models import AgentRegistration, MonitorRequest, TenantCreate
from ai_guardian.security import stable_hash
from ai_guardian.service import GuardianService


def run_demo() -> None:
    settings = Settings(
        service_name="AI Guardian Demo",
        bootstrap_api_keys=("bootstrap-demo",),
        database_path=":memory:",
        blocked_domains=("pastebin.com",),
        default_allowed_domains=("github.com", "myproduct.com"),
        suspicious_phrases=("ignore previous instructions", "disable guard"),
        webhook_urls=(),
        rate_limit_per_minute=120,
    )
    service = GuardianService(settings)
    bootstrap = service.bootstrap_tenant(
        TenantCreate(
            name="Armpit Symphony",
            slug="armpit-symphony-demo",
            contact_email="ops@myproduct.com",
            plan="growth",
        )
    )
    access = service.authenticate(bootstrap.api_key)
    assert access is not None
    registration = service.register_agent(
        access,
        AgentRegistration(
            name="prod-bot",
            owner="armpit-symphony",
            description="Monitors production automation for your bots and site.",
            allowed_domains=["github.com", "myproduct.com"],
        ),
    )
    agent = MockAgent(agent_id=registration.agent_id)

    print("AI Guardian SaaS demo")
    print(f"Tenant: {bootstrap.tenant.slug}")
    print(f"Admin API key: {bootstrap.api_key}")
    print(f"Registered agent: {registration.agent_id}")
    print()

    actions = [
        agent.perform_action("Check release notes", source_url="https://github.com/armpit-symphony/Ai-Guardian"),
        agent.perform_action("Upload logs", source_url="https://pastebin.com/raw/12345"),
        agent.perform_action("Update homepage", source_url="https://myproduct.com/admin"),
    ]

    actions[2]["context_checksum"] = stable_hash({"context": "approved_state"})

    for item in actions:
        request = MonitorRequest(**item)
        result = service.monitor(access, request)
        print(f"Action: {request.action}")
        print(f"Decision: {result.decision}")
        print(f"Anomaly: {result.anomaly}")
        print(f"Findings: {[finding.code for finding in result.findings]}")
        print(f"Proof valid: {service.verify_proof(access, result.proof)}")
        print("---")


if __name__ == "__main__":
    run_demo()
