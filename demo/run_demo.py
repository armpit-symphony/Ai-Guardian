from src.agent_sim import MockAgent
from src.guardian import Guardian

def run_demo():
    agent = MockAgent()
    guardian = Guardian()
    
    print("Starting Version 1 Demo...")
    actions = ["safe action 1", "safe action 2", "unauthorized action", "safe action 3", "safe action 4"]
    
    for action in actions:
        agent_data = agent.perform_action(action)
        result = guardian.monitor_action(agent_data["action"], agent_data["context"])
        print(f"Action: {action}")
        print(f"Anomaly: {result['anomaly']}")
        print(f"Proof: {result['proof']}")
        print(f"Verification: {guardian.verify_proof(result['proof'])}")
        print("---")

if __name__ == "__main__":
    run_demo()
