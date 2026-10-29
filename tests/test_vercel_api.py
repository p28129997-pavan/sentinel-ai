from fastapi.testclient import TestClient

from api import server


def test_root_vercel_entrypoint_exports_fastapi_app():
    from server import app as vercel_app

    assert vercel_app is server.app


def configure_admin(monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "a-very-long-test-password")
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret-with-at-least-32-bytes")
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)


def test_health_reports_backend_and_missing_admin_config(monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    response = TestClient(server.app).get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "online",
        "service": "sentinel-ai-api",
        "detection": "ready",
        "admin_configured": False,
        "database_configured": False,
    }


def test_dashboard_is_served_by_the_backend():
    client = TestClient(server.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "Sentinel AI" in response.text
    assert client.get("/app.js").status_code == 200


def test_detection_endpoint_runs_the_pipeline():
    response = TestClient(server.app).get("/api/detections")
    repeated = server._run_detection()

    assert response.status_code == 200
    result = response.json()
    assert len(result["events"]) == 28
    assert result["metrics"]["campaigns_detected"] == 3
    assert {incident["campaign_tag"] for incident in result["incidents"]} >= {
        "CAMPAIGN_ALPHA",
        "CAMPAIGN_BRAVO",
        "CAMPAIGN_CHARLIE",
    }
    assert [item["incident_id"] for item in result["incidents"]] == [
        item["incident_id"] for item in repeated["incidents"]
    ]
    assert [
        action["action_id"]
        for incident in result["incidents"]
        for action in incident["recommended_actions"]
    ] == [
        action["action_id"]
        for incident in repeated["incidents"]
        for action in incident["recommended_actions"]
    ]


def test_url_inspection_runs_on_the_backend():
    response = TestClient(server.app).post(
        "/api/inspect",
        json={"url": "http://paypa1-login.xyz/verify"},
    )

    assert response.status_code == 200
    assert response.json()["verdict"] == "MALICIOUS / PHISHING"
    assert response.json()["risk_score"] == 100


def test_email_inspection_runs_phishing_rules_on_the_backend():
    response = TestClient(server.app).post(
        "/api/inspect/email",
        json={
            "sender": "billing@invoice-secure-portal.xyz",
            "subject": "Urgent: Invoice Overdue - Action Required",
            "spf_status": "FAIL",
            "attachments": ["invoice.xlsm"],
            "urls": ["http://paypa1-login.xyz/verify"],
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "MALICIOUS / PHISHING"
    assert result["risk_score"] == 100
    assert {
        finding["rule_id"] for finding in result["findings"]
    } == {
        "RULE_EMAIL_PHISHING_KEYWORD",
        "RULE_EMAIL_SUSPICIOUS_SENDER_DOMAIN",
        "RULE_EMAIL_MALICIOUS_ATTACHMENT",
        "RULE_EMAIL_SUSPICIOUS_URL",
    }


def test_admin_login_sets_http_only_same_site_cookie(monkeypatch):
    configure_admin(monkeypatch)
    client = TestClient(server.app)

    response = client.post(
        "/api/admin/login",
        json={"password": "a-very-long-test-password"},
    )

    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert client.get("/api/admin/session").json()["authenticated"] is True


def test_admin_rejects_bad_password_and_protects_approval_queue(monkeypatch):
    configure_admin(monkeypatch)
    client = TestClient(server.app)

    bad_login = client.post("/api/admin/login", json={"password": "incorrect"})
    unauthorized_queue = client.get("/api/admin/approvals")

    assert bad_login.status_code == 401
    assert unauthorized_queue.status_code == 401


def test_admin_queue_reports_missing_postgres_configuration(monkeypatch):
    configure_admin(monkeypatch)
    client = TestClient(server.app)
    client.post("/api/admin/login", json={"password": "a-very-long-test-password"})

    response = client.get("/api/admin/approvals")

    assert response.status_code == 503
    assert "Postgres database" in response.json()["detail"]


def test_approval_decisions_are_persisted_after_admin_auth(monkeypatch):
    configure_admin(monkeypatch)
    client = TestClient(server.app)
    client.post("/api/admin/login", json={"password": "a-very-long-test-password"})
    action = {
        "action_id": "ACT-0123456789ABCDEF",
        "incident_id": "INC-0123456789ABCDEF",
        "action_type": "BLOCK_INDICATOR",
        "target_entity": "198.51.100.45",
    }
    monkeypatch.setattr(server, "_get_admin_actions", lambda: [action])

    class FakeConnection:
        def __init__(self):
            self.statements = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query, parameters=None):
            self.statements.append((query, parameters))

    connection = FakeConnection()
    monkeypatch.setattr(server, "_connect_database", lambda: connection)

    response = client.post(
        "/api/admin/decisions",
        json={
            "action_id": action["action_id"],
            "decision": "APPROVE",
            "reviewer_name": "Analyst",
            "reviewer_notes": "Confirmed in synthetic evidence.",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "saved"
    assert response.json()["execution_log"]["status"] == "SIMULATED_SUCCESS"
    assert len(connection.statements) == 2
    assert "ON CONFLICT (action_id)" in connection.statements[-1][0]
