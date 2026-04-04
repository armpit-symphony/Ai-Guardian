from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MockAgent:
    agent_id: str
    memory: dict[str, str] = field(default_factory=lambda: {"context": "initial_state"})

    def perform_action(self, action: str, source_url: str | None = None) -> dict:
        if "update" in action.lower():
            self.memory["context"] = "updated_state"
        return {"agent_id": self.agent_id, "action": action, "context": dict(self.memory), "source_url": source_url}
