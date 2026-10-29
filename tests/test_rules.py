import pytest
from detection.rules import RuleEngine

@pytest.fixture
def rule_engine():
    return RuleEngine()

def test_email_phishing_keywords(rule_engine):
    event = {
        "subject": "Urgent: Action required on invoice overdue",
        "sender": "external@unknown.com",
        "spf_status": "PASS",
        "attachments": []
    }
    triggered = rule_engine.evaluate_email_event(event)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_EMAIL_PHISHING_KEYWORD" in rule_ids

def test_email_untrusted_domain_and_spf_fail(rule_engine):
    event = {
        "subject": "Weekly Update",
        "sender": "attacker@fake-login.xyz",
        "spf_status": "FAIL",
        "attachments": []
    }
    triggered = rule_engine.evaluate_email_event(event)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_EMAIL_SUSPICIOUS_SENDER_DOMAIN" in rule_ids

def test_email_macro_attachment(rule_engine):
    event = {
        "subject": "Quarterly Statements",
        "sender": "payroll@example.com",
        "spf_status": "PASS",
        "attachments": ["Payroll_Data.xlsm"]
    }
    triggered = rule_engine.evaluate_email_event(event)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_EMAIL_MALICIOUS_ATTACHMENT" in rule_ids

def test_auth_failed_burst(rule_engine):
    events = [
        {"auth_status": "FAILURE", "timestamp": "2026-10-28T10:00:00Z"},
        {"auth_status": "FAILURE", "timestamp": "2026-10-28T10:01:00Z"},
        {"auth_status": "FAILURE", "timestamp": "2026-10-28T10:02:00Z"}
    ]
    triggered = rule_engine.evaluate_auth_events(events)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_AUTH_FAILED_BURST" in rule_ids

def test_auth_impossible_travel(rule_engine):
    events = [
        {"auth_status": "SUCCESS", "location_country": "US", "timestamp": "2026-10-28T10:00:00Z"},
        {"auth_status": "FAILURE", "location_country": "RU", "timestamp": "2026-10-28T10:15:00Z"}
    ]
    triggered = rule_engine.evaluate_auth_events(events)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_AUTH_IMPOSSIBLE_TRAVEL" in rule_ids

def test_auth_mfa_fatigue_bypass(rule_engine):
    events = [
        {"auth_status": "FAILURE", "failure_reason": "MFA_PUSH_REJECTED", "mfa_status": "DENIED"},
        {"auth_status": "SUCCESS", "mfa_status": "ACCEPTED_AFTER_DENIALS"}
    ]
    triggered = rule_engine.evaluate_auth_events(events)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_AUTH_MFA_FATIGUE_BYPASS" in rule_ids

def test_auth_privilege_escalation(rule_engine):
    events = [
        {"user_id": "svc_backup", "auth_method": "LOCAL_ADMIN_ELEVATION", "device_id": "WKS-1"}
    ]
    triggered = rule_engine.evaluate_auth_events(events)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_AUTH_PRIVILEGE_ESCALATION" in rule_ids

def test_network_c2_port(rule_engine):
    events = [
        {"dst_port": 4444, "dst_ip": "198.51.100.45", "bytes_sent": 500}
    ]
    triggered = rule_engine.evaluate_network_events(events)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_NET_SUSPICIOUS_C2_PORT" in rule_ids

def test_network_high_volume_exfiltration(rule_engine):
    events = [
        {"dst_port": 443, "src_ip": "10.0.1.5", "dst_ip": "198.51.100.99", "bytes_sent": 75000000}
    ]
    triggered = rule_engine.evaluate_network_events(events)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_NET_HIGH_VOLUME_EXFILTRATION" in rule_ids

def test_network_beaconing_pattern(rule_engine):
    events = [
        {"dst_ip": "203.0.113.88", "dst_port": 8888, "bytes_sent": 128},
        {"dst_ip": "203.0.113.88", "dst_port": 8888, "bytes_sent": 130},
        {"dst_ip": "203.0.113.88", "dst_port": 8888, "bytes_sent": 129}
    ]
    triggered = rule_engine.evaluate_network_events(events)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "RULE_NET_BEACONING_PATTERN" in rule_ids
