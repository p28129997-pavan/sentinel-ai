import pytest
from detection.correlation import CorrelationEngine

@pytest.fixture
def correlation_engine():
    return CorrelationEngine()

def test_multi_source_correlation_chain(correlation_engine):
    # Coordinated attack: Email -> Auth -> Network
    email_logs = [{
        "event_id": "TEST-EML-1",
        "timestamp": "2026-10-28T10:00:00Z",
        "sender": "hacker@evil-domain.xyz",
        "recipient": "victim@corp.local",
        "user_id": "victim",
        "subject": "Urgent Action Required",
        "spf_status": "FAIL",
        "client_ip": "198.51.100.1"
    }]
    auth_logs = [
        {"event_id": "TEST-ATH-1", "timestamp": "2026-10-28T10:10:00Z", "user_id": "victim", "device_id": "DEV-1", "source_ip": "198.51.100.1", "auth_status": "FAILURE"},
        {"event_id": "TEST-ATH-2", "timestamp": "2026-10-28T10:11:00Z", "user_id": "victim", "device_id": "DEV-1", "source_ip": "198.51.100.1", "auth_status": "FAILURE"},
        {"event_id": "TEST-ATH-3", "timestamp": "2026-10-28T10:12:00Z", "user_id": "victim", "device_id": "DEV-1", "source_ip": "198.51.100.1", "auth_status": "FAILURE"},
        {"event_id": "TEST-ATH-4", "timestamp": "2026-10-28T10:15:00Z", "user_id": "victim", "device_id": "DEV-1", "source_ip": "198.51.100.1", "auth_status": "SUCCESS"}
    ]
    network_logs = [{
        "event_id": "TEST-NET-1",
        "timestamp": "2026-10-28T10:25:00Z",
        "device_id": "DEV-1",
        "user_id": "victim",
        "src_ip": "10.0.1.15",
        "dst_ip": "198.51.100.1",
        "dst_port": 4444,
        "bytes_sent": 80000000
    }]

    norm = correlation_engine.normalize_events(email_logs, auth_logs, network_logs)
    incidents = correlation_engine.correlate(norm)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["severity"] == "CRITICAL"
    assert inc["risk_score"] >= 85.0
    assert inc["evidence"]["sequence_matched"] is True
    assert set(inc["evidence"]["sources"]) == {"EMAIL", "AUTH", "NETWORK"}

def test_unrelated_events_not_combined(correlation_engine):
    # Two completely unrelated users in different departments and distinct IPs
    email_logs = [{
        "event_id": "USER-A-EML",
        "timestamp": "2026-10-28T10:00:00Z",
        "sender": "hacker@evil-domain.xyz",
        "recipient": "usera@corp.local",
        "user_id": "usera",
        "subject": "Urgent Action Required",
        "spf_status": "FAIL",
        "client_ip": "198.51.100.10"
    }]
    network_logs = [{
        "event_id": "USER-B-NET",
        "timestamp": "2026-10-28T10:05:00Z",
        "device_id": "DEV-B-88",
        "user_id": "userb",
        "src_ip": "10.0.9.9",
        "dst_ip": "203.0.113.99",
        "dst_port": 4444,
        "bytes_sent": 60000000
    }]

    norm = correlation_engine.normalize_events(email_logs, [], network_logs)
    incidents = correlation_engine.correlate(norm)

    # Should produce 2 separate incidents, NOT combined into 1
    assert len(incidents) == 2
    users = {i["primary_user"] for i in incidents}
    assert users == {"usera", "userb"}

def test_time_window_boundary_enforcement(correlation_engine):
    # Events sharing user, but separated by 48 hours (outside 60m window)
    email_logs = [{
        "event_id": "OLD-EML",
        "timestamp": "2026-10-26T10:00:00Z",
        "sender": "offers@cheap-discounts-online.xyz",
        "user_id": "alice",
        "subject": "Discount Voucher Urgent",
        "spf_status": "FAIL"
    }]
    network_logs = [{
        "event_id": "NEW-NET",
        "timestamp": "2026-10-28T10:00:00Z",
        "device_id": "ALICE-WKS",
        "user_id": "alice",
        "src_ip": "10.0.1.10",
        "dst_ip": "198.51.100.22",
        "dst_port": 4444,
        "bytes_sent": 90000000
    }]

    norm = correlation_engine.normalize_events(email_logs, [], network_logs)
    incidents = correlation_engine.correlate(norm)

    # Must NOT be merged into a single multi-source campaign
    assert len(incidents) == 2
    for inc in incidents:
        # Neither incident contains both events
        eids = [e["event_id"] for e in inc["correlated_events"]]
        assert not ("OLD-EML" in eids and "NEW-NET" in eids)

def test_missing_fields_and_duplicates_handled_safely(correlation_engine):
    # Missing user_id in network event, duplicate auth event
    email_logs = [{
        "event_id": "EML-SAFE-1",
        "timestamp": "2026-10-28T10:00:00Z",
        "sender": "hr@fake-phish.xyz",
        "recipient": "charlie@corp.local",
        "user_id": "charlie",
        "subject": "Action Required",
        "spf_status": "FAIL"
    }]
    auth_logs = [
        {"event_id": "ATH-DUP", "timestamp": "2026-10-28T10:05:00Z", "user_id": "charlie", "device_id": "DEV-CHARLIE", "auth_status": "FAILURE", "failure_reason": "PWD"},
        {"event_id": "ATH-DUP", "timestamp": "2026-10-28T10:05:00Z", "user_id": "charlie", "device_id": "DEV-CHARLIE", "auth_status": "FAILURE", "failure_reason": "PWD"}
    ]
    network_logs = [{
        "event_id": "NET-MISSING-USER",
        "timestamp": "2026-10-28T10:10:00Z",
        "device_id": "DEV-CHARLIE",
        "user_id": None, # Missing field
        "src_ip": "10.0.3.33",
        "dst_ip": "198.51.100.33",
        "dst_port": 4444,
        "bytes_sent": 60000000
    }]

    norm = correlation_engine.normalize_events(email_logs, auth_logs, network_logs)
    # Verify deduplication reduced the duplicate auth event
    auth_normalized = [e for e in norm if e["source"] == "AUTH"]
    assert len(auth_normalized) == 1

    incidents = correlation_engine.correlate(norm)
    assert len(incidents) == 1
    # Check that missing user_id was safely resolved via DEV-CHARLIE device mapping
    assert incidents[0]["primary_user"] == "charlie"
    assert incidents[0]["primary_device"] == "DEV-CHARLIE"

def test_benign_activity_does_not_become_attack(correlation_engine):
    # Normal benign browsing and login
    email_logs = [{
        "event_id": "BENIGN-EML",
        "timestamp": "2026-10-28T09:00:00Z",
        "sender": "team@corp.local",
        "recipient": "dan@corp.local",
        "user_id": "dan",
        "subject": "Team Lunch today",
        "spf_status": "PASS",
        "dkim_status": "PASS"
    }]
    auth_logs = [{
        "event_id": "BENIGN-ATH",
        "timestamp": "2026-10-28T09:05:00Z",
        "user_id": "dan",
        "device_id": "DAN-LPT",
        "source_ip": "10.0.1.20",
        "auth_status": "SUCCESS"
    }]
    network_logs = [{
        "event_id": "BENIGN-NET",
        "timestamp": "2026-10-28T09:10:00Z",
        "device_id": "DAN-LPT",
        "user_id": "dan",
        "src_ip": "10.0.1.20",
        "dst_ip": "192.0.2.1",
        "dst_port": 443,
        "bytes_sent": 5000
    }]

    norm = correlation_engine.normalize_events(email_logs, auth_logs, network_logs)
    incidents = correlation_engine.correlate(norm)

    # Benign events trigger zero rules and should not create attack incidents
    assert len(incidents) == 0
