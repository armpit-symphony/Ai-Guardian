from fastapi import FastAPI
from pydantic import BaseModel
from .guardian import Guardian

app = FastAPI()
guardian = Guardian()

class MonitorRequest(BaseModel):
    action: str
    context: dict

@app.post("/monitor")
def monitor_agent(request: MonitorRequest):
    result = guardian.monitor_action(request.action, request.context)
    return {"status": "ok" if result["anomaly"] == False else "anomaly detected", "proof": result["proof"]}

@app.get("/verify/{proof_hash}")
def verify_proof(proof_hash: str):
    is_valid = guardian.verify_proof(proof_hash)
    return {"valid": is_valid}
