import pytest
from src.guardian import Guardian

def test_monitor_no_anomaly():
    g = Guardian()
    result = g.monitor_action("safe action", {"key": "value"})
    assert result["anomaly"] == False
    assert len(result["proof"]) == 64  # SHA-256 hex length

def test_monitor_anomaly():
    g = Guardian()
    result = g.monitor_action("unauthorized access", {"key": "value"})
    assert result["anomaly"] == True

def test_verify_proof():
    g = Guardian()
    result = g.monitor_action("test", {})
    assert g.verify_proof(result["proof"]) == True
    assert g.verify_proof("invalid") == False
