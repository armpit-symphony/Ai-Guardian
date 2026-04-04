from __future__ import annotations

from dataclasses import dataclass

from .models import EvaluationFinding, MonitorRequest
from .security import extract_domain, find_secret_exposures, stable_hash


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class PolicyContext:
    blocked_domains: tuple[str, ...]
    suspicious_phrases: tuple[str, ...]
    allowed_domains: tuple[str, ...]


class PolicyEngine:
    def evaluate(self, request: MonitorRequest, policy: PolicyContext) -> tuple[str, list[EvaluationFinding], str]:
        findings: list[EvaluationFinding] = []
        proof_payload = {
            "agent_id": request.agent_id,
            "action": request.action,
            "context": request.context,
            "source_url": request.source_url,
            "metadata": request.metadata,
        }
        proof = stable_hash(proof_payload)

        action_lower = request.action.lower()
        context_blob = f"{request.action}\n{request.context}\n{request.metadata}"
        context_lower = context_blob.lower()

        if request.context_checksum:
            actual_checksum = stable_hash(request.context)
            if actual_checksum != request.context_checksum:
                findings.append(
                    EvaluationFinding(
                        code="context_tamper",
                        severity="critical",
                        message="Context checksum mismatch indicates memory or prompt tampering.",
                    )
                )

        domain = extract_domain(request.source_url)
        if domain:
            if domain in policy.blocked_domains:
                findings.append(
                    EvaluationFinding(
                        code="blocked_domain",
                        severity="critical",
                        message=f"Action references blocked domain '{domain}'.",
                    )
                )
            elif policy.allowed_domains and domain not in policy.allowed_domains:
                findings.append(
                    EvaluationFinding(
                        code="unknown_domain",
                        severity="medium",
                        message=f"Domain '{domain}' is outside the approved allowlist.",
                    )
                )

        for phrase in policy.suspicious_phrases:
            if phrase in context_lower:
                findings.append(
                    EvaluationFinding(
                        code="prompt_injection",
                        severity="high",
                        message=f"Suspicious instruction detected: '{phrase}'.",
                    )
                )
                break

        for exposure in find_secret_exposures(context_blob):
            findings.append(
                EvaluationFinding(
                    code=exposure,
                    severity="critical",
                    message="Potential credential or token exposure detected in the action payload.",
                )
            )

        if "delete" in action_lower or "deploy" in action_lower:
            findings.append(
                EvaluationFinding(
                    code="high_impact_action",
                    severity="medium",
                    message="High-impact action should be reviewed before execution.",
                )
            )

        decision = self._decide(findings)
        return decision, findings, proof

    def _decide(self, findings: list[EvaluationFinding]) -> str:
        highest = max((SEVERITY_RANK[item.severity] for item in findings), default=0)
        if highest >= SEVERITY_RANK["critical"]:
            return "block"
        if highest >= SEVERITY_RANK["medium"]:
            return "review"
        return "allow"
