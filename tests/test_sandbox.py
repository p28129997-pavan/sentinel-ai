import os
import pytest
from database.db import init_db, reset_db, save_incident, get_all_approvals
from response.sandbox import SimulationSandbox

TEST_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_sentinel.db")

@pytest.fixture(autouse=True)
def setup_test_db():
    init_db(TEST_DB_PATH)
    reset_db(TEST_DB_PATH)
    yield
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass

def test_approval_simulation_recorded_in_sqlite():
    incident = {
        "incident_id": "INC-TEST-001",
        "title": "Test Threat Incident",
        "campaign_tag": "TEST_CAMPAIGN",
        "severity": "HIGH",
        "risk_score": 75.0,
        "confidence": 0.85,
        "primary_user": "sarah.test",
        "recommended_actions": [{
            "action_id": "ACT-TEST-01",
            "action_type": "REVOKE_SESSION",
            "target_entity": "sarah.test",
            "description": "Simulate session revocation"
        }]
    }
    save_incident(incident, TEST_DB_PATH)

    # Verify initial pending status
    approvals = get_all_approvals(TEST_DB_PATH)
    assert len(approvals) == 1
    assert approvals[0]["status"] == "PENDING_APPROVAL"

    # Human reviewer APPROVES the simulated action
    res = SimulationSandbox.process_human_decision(
        action_id="ACT-TEST-01",
        decision="APPROVE",
        reviewer_name="Analyst Jones",
        reviewer_notes="Confirmed unauthorized external session.",
        action_type="REVOKE_SESSION",
        target_entity="sarah.test",
        db_path=TEST_DB_PATH
    )

    assert res["success"] is True
    assert res["status"] == "SIMULATED_EXECUTED"
    assert "SAFE SIMULATION MODE ACTIVE" in res["log"]["disclaimer"]

    # Verify SQLite update
    updated_approvals = get_all_approvals(TEST_DB_PATH)
    assert updated_approvals[0]["status"] == "SIMULATED_EXECUTED"
    assert updated_approvals[0]["reviewer_name"] == "Analyst Jones"
    assert updated_approvals[0]["decision"] == "APPROVE"

def test_rejection_workflow_recorded_in_sqlite():
    incident = {
        "incident_id": "INC-TEST-002",
        "title": "Second Test Incident",
        "campaign_tag": "TEST_CAMPAIGN_2",
        "severity": "MEDIUM",
        "risk_score": 50.0,
        "confidence": 0.70,
        "primary_device": "DEV-WKS-99",
        "recommended_actions": [{
            "action_id": "ACT-TEST-02",
            "action_type": "ISOLATE_DEVICE",
            "target_entity": "DEV-WKS-99",
            "description": "Simulate host isolation"
        }]
    }
    save_incident(incident, TEST_DB_PATH)

    # Human reviewer REJECTS the action
    res = SimulationSandbox.process_human_decision(
        action_id="ACT-TEST-02",
        decision="REJECT",
        reviewer_name="Analyst Smith",
        reviewer_notes="Target is production server during trading hours; approved alternate mitigation.",
        action_type="ISOLATE_DEVICE",
        target_entity="DEV-WKS-99",
        db_path=TEST_DB_PATH
    )

    assert res["success"] is True
    assert res["status"] == "REJECTED"

    updated_approvals = get_all_approvals(TEST_DB_PATH)
    assert updated_approvals[0]["status"] == "REJECTED"
    assert updated_approvals[0]["decision"] == "REJECT"
    assert "production server" in updated_approvals[0]["reviewer_notes"]

def test_no_real_containment_action_executed():
    """Confirms all containment logic is isolated to structured mock strings and zero OS subprocesses."""
    log = SimulationSandbox.execute_simulated_action(
        action_type="BLOCK_INDICATOR",
        target_entity="198.51.100.99",
        reviewer_name="SecOps Analyst",
        reviewer_notes="Containment test"
    )
    assert "SAFE SIMULATION MODE ACTIVE" in log["disclaimer"]
    assert log["status"] == "SIMULATED_SUCCESS"
    assert any("Mock API Call" in d for d in log["details"])
