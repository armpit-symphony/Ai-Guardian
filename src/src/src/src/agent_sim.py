class MockAgent:
    def __init__(self):
        self.memory = {"context": "initial_state"}

    def perform_action(self, action: str):
        if "update" in action:
            self.memory["context"] = "updated_state"
        return {"action": action, "context": self.memory}
