import hashlib
import json

class Guardian:
    def __init__(self):
        self.proof_chain = []  # Simulates decentralized proof chain (like blockchain)

    def _hash_data(self, data):
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def monitor_action(self, action: str, context: dict):
        # Simulate anomaly detection
        anomaly = False
        if 'unauthorized' in action.lower():  # Mock rule
            anomaly = True

        # Generate proof
        current_data = {"action": action, "context": context}
        current_hash = self._hash_data(current_data)
        if self.proof_chain:
            current_hash = self._hash_data({"prev": self.proof_chain[-1], "current": current_hash})
        self.proof_chain.append(current_hash)

        return {"anomaly": anomaly, "proof": current_hash}

    def verify_proof(self, proof_hash: str):
        # Simple verification: check if in chain
        return proof_hash in self.proof_chain
