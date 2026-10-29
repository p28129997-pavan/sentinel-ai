import base64
import hashlib
import hmac
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from psycopg.types.json import Jsonb

from detection.rules import RuleEngine, URLAnalyzer
from pipeline import run_detection_pipeline
from response.sandbox import SimulationSandbox

app = FastAPI(title="Sentinel AI API", docs_url="/api/docs", openapi_url="/api/openapi.json")
SESSION_COOKIE = "sentinel_admin"
SESSION_DURATION_SECONDS = 8 * 60 * 60
ROOT = Path(__file__).resolve().parents[1]


@app.middleware("http")
async def disable_api_caching(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


class InspectRequest(BaseModel):
    url: str = Field(max_length=2048)


class EmailInspectRequest(BaseModel):
    sender: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=500)
    spf_status: str = Field(default="", max_length=20)
    dkim_status: str = Field(default="", max_length=20)
    dmarc_status: str = Field(default="", max_length=20)
    urls: list[str] = Field(default_factory=list, max_length=10)
    attachments: list[str] = Field(default_factory=list, max_length=20)


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class DecisionRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=128)
    decision: str
    reviewer_name: str = Field(min_length=1, max_length=120)
    reviewer_notes: str = Field(default="", max_length=2000)


def _session_secret() -> bytes:
    password = os.environ.get("ADMIN_PASSWORD", "")
    secret = os.environ.get("SESSION_SECRET", "")
    if len(password) < 16 or len(secret.encode("utf-8")) < 32:
        raise HTTPException(
            status_code=503,
            detail=(
                "Admin access is not configured. Set ADMIN_PASSWORD (at least "
                "16 characters) and SESSION_SECRET (at least 32 characters) "
                "in the Vercel project environment."
            ),
        )
    return secret.encode("utf-8")


def _make_session(secret: bytes) -> str:
    expires_at = int(time.time()) + SESSION_DURATION_SECONDS
    message = str(expires_at).encode("ascii")
    signature = hmac.new(secret, message, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{expires_at}.{encoded_signature}"


def _valid_session(token: str | None) -> bool:
    if not token:
        return False
    try:
        expires_text, supplied_signature = token.split(".", 1)
        expires_at = int(expires_text)
        if expires_at <= int(time.time()) or expires_at > int(time.time()) + SESSION_DURATION_SECONDS:
            return False
        expected = _make_signature(_session_secret(), expires_text)
        return hmac.compare_digest(supplied_signature, expected)
    except (ValueError, HTTPException):
        return False


def _make_signature(secret: bytes, expires_text: str) -> str:
    signature = hmac.new(secret, expires_text.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _require_admin(request: Request) -> None:
    if not _valid_session(request.cookies.get(SESSION_COOKIE)):
        raise HTTPException(status_code=401, detail="Admin sign-in is required.")


def _database_url() -> str:
    database_url = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL")
    if not database_url:
        raise HTTPException(
            status_code=503,
            detail=(
                "Durable admin decisions require a Postgres database. Add a "
                "Vercel Postgres integration or set POSTGRES_URL in the "
                "project environment."
            ),
        )
    return database_url


def _connect_database() -> psycopg.Connection:
    try:
        return psycopg.connect(_database_url(), connect_timeout=5)
    except HTTPException:
        raise
    except psycopg.Error as error:
        raise HTTPException(
            status_code=503,
            detail="Could not connect to the admin database. Check POSTGRES_URL.",
        ) from error


def _ensure_decisions_table(connection: psycopg.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS sentinel_admin_decisions (
            action_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target_entity TEXT NOT NULL,
            decision TEXT NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
            reviewer_name TEXT NOT NULL,
            reviewer_notes TEXT NOT NULL,
            reviewed_at TIMESTAMPTZ NOT NULL,
            execution_log JSONB NOT NULL
        )
        """
    )


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def _run_detection() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temp_dir:
        result = run_detection_pipeline(
            db_path=str(Path(temp_dir) / "sentinel.db"),
            data_dir=str(ROOT / "data"),
        )

    incidents = result["incidents"]
    for incident in incidents:
        event_ids = sorted(
            event.get("event_id", "")
            for event in incident.get("correlated_events", [])
        )
        incident_id = _stable_id(
            "INC",
            incident.get("campaign_tag", ""),
            incident.get("primary_user", "") or "",
            *event_ids,
        )
        incident["incident_id"] = incident_id
        for action in incident.get("recommended_actions", []):
            action["action_id"] = _stable_id(
                "ACT",
                incident_id,
                action.get("action_type", ""),
                action.get("target_entity", "") or "",
            )

    events = [
        {
            key: event.get(key)
            for key in (
                "event_id",
                "source",
                "timestamp",
                "user_id",
                "device_id",
                "ip_address",
                "scenario_tag",
                "summary",
            )
        }
        for event in result["events"]
    ]
    return {
        "generated_at": incidents[0].get("detected_at") if incidents else None,
        "events": events,
        "incidents": incidents,
        "metrics": result["metrics"],
    }


def _get_admin_actions() -> list[dict[str, Any]]:
    with _connect_database() as connection:
        _ensure_decisions_table(connection)
        rows = connection.execute(
            """
            SELECT action_id, decision, reviewer_name, reviewer_notes,
                   reviewed_at, execution_log
            FROM sentinel_admin_decisions
            """
        ).fetchall()
    dashboard = _run_detection()
    actions = []
    for incident in dashboard["incidents"]:
        for action in incident.get("recommended_actions", []):
            actions.append(
                {
                    **action,
                    "incident_id": incident["incident_id"],
                    "incident_title": incident.get("title"),
                    "campaign_tag": incident.get("campaign_tag"),
                }
            )
    saved = {
        row[0]: {
            "decision": row[1],
            "reviewer_name": row[2],
            "reviewer_notes": row[3],
            "reviewed_at": row[4].isoformat() if row[4] else None,
            "execution_log": row[5],
        }
        for row in rows
    }
    return [
        {
            **action,
            "review": saved.get(action["action_id"]),
        }
        for action in actions
    ]


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "online",
        "service": "sentinel-ai-api",
        "detection": "ready",
        "admin_configured": (
            len(os.environ.get("ADMIN_PASSWORD", "")) >= 16
            and len(os.environ.get("SESSION_SECRET", "").encode("utf-8")) >= 32
        ),
        "database_configured": bool(
            os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL")
        ),
    }


@app.get("/api/detections")
def detections() -> dict[str, Any]:
    try:
        return _run_detection()
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="The detection pipeline failed to process telemetry."
        ) from error


@app.post("/api/inspect")
def inspect_url(payload: InspectRequest) -> dict[str, Any]:
    try:
        return URLAnalyzer.analyze_url(payload.url)
    except Exception as error:
        raise HTTPException(status_code=400, detail="The URL could not be analyzed.") from error


@app.post("/api/inspect/email")
def inspect_email(payload: EmailInspectRequest) -> dict[str, Any]:
    try:
        findings = RuleEngine().evaluate_email_event(payload.model_dump())
    except Exception as error:
        raise HTTPException(status_code=400, detail="The email could not be analyzed.") from error

    risk_score = min(100, sum(int(item.get("base_weight", 0)) for item in findings))
    verdict = (
        "MALICIOUS / PHISHING"
        if risk_score >= 70
        else "SUSPICIOUS"
        if risk_score >= 35
        else "BENIGN / SAFE"
    )
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "findings": findings,
        "disclaimer": "Heuristic detection result; verify the original message and its context.",
    }


@app.get("/api/admin/session")
def admin_session(request: Request) -> dict[str, bool]:
    configured = (
        len(os.environ.get("ADMIN_PASSWORD", "")) >= 16
        and len(os.environ.get("SESSION_SECRET", "").encode("utf-8")) >= 32
    )
    return {
        "configured": configured,
        "authenticated": configured and _valid_session(request.cookies.get(SESSION_COOKIE)),
    }


@app.post("/api/admin/login")
def admin_login(payload: LoginRequest, request: Request, response: Response) -> dict[str, str]:
    secret = _session_secret()
    expected_password = os.environ["ADMIN_PASSWORD"].encode("utf-8")
    supplied_password = payload.password.encode("utf-8")
    if not hmac.compare_digest(supplied_password, expected_password):
        raise HTTPException(status_code=401, detail="Invalid admin password.")

    response.set_cookie(
        key=SESSION_COOKIE,
        value=_make_session(secret),
        max_age=SESSION_DURATION_SECONDS,
        secure=request.url.scheme == "https" or os.environ.get("VERCEL") == "1",
        httponly=True,
        samesite="strict",
        path="/api/admin",
    )
    return {"status": "signed_in"}


@app.post("/api/admin/logout")
def admin_logout(response: Response) -> dict[str, str]:
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/api/admin",
        secure=os.environ.get("VERCEL") == "1",
        httponly=True,
        samesite="strict",
    )
    return {"status": "signed_out"}


@app.get("/api/admin/approvals")
def admin_approvals(request: Request) -> dict[str, Any]:
    _require_admin(request)
    try:
        return {"actions": _get_admin_actions()}
    except HTTPException:
        raise
    except psycopg.Error as error:
        raise HTTPException(
            status_code=503, detail="Could not read admin decisions from Postgres."
        ) from error
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Could not load the admin approval queue."
        ) from error


@app.post("/api/admin/decisions")
def admin_decision(
    payload: DecisionRequest, request: Request
) -> dict[str, Any]:
    _require_admin(request)
    decision = payload.decision.upper()
    if decision not in {"APPROVE", "REJECT"}:
        raise HTTPException(status_code=422, detail="Decision must be APPROVE or REJECT.")
    if not payload.reviewer_name.strip():
        raise HTTPException(status_code=422, detail="Reviewer name cannot be blank.")
    if not re.fullmatch(r"ACT-[A-F0-9]{16}", payload.action_id):
        raise HTTPException(status_code=422, detail="Invalid action identifier.")

    try:
        actions = _get_admin_actions()
        action = next(
            (item for item in actions if item["action_id"] == payload.action_id),
            None,
        )
        if action is None:
            raise HTTPException(
                status_code=404, detail="That action is not in the current detection results."
            )

        execution_log = (
            SimulationSandbox.execute_simulated_action(
                action_type=action["action_type"],
                target_entity=action["target_entity"],
                reviewer_name=payload.reviewer_name.strip(),
                reviewer_notes=payload.reviewer_notes.strip(),
            )
            if decision == "APPROVE"
            else {
                "engine": "SENTINEL-SIMULATOR-v1.0",
                "action": action["action_type"],
                "target": action["target_entity"],
                "status": "REJECTED_BY_OPERATOR",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "disclaimer": SimulationSandbox.SIMULATION_DISCLAIMER,
                "details": [
                    f"Action rejected by reviewer '{payload.reviewer_name.strip()}'.",
                    f"Reason for rejection: {payload.reviewer_notes.strip()}",
                    "Containment action cancelled; no changes simulated.",
                ],
            }
        )

        with _connect_database() as connection:
            _ensure_decisions_table(connection)
            connection.execute(
                """
                INSERT INTO sentinel_admin_decisions (
                    action_id, incident_id, action_type, target_entity, decision,
                    reviewer_name, reviewer_notes, reviewed_at, execution_log
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s)
                ON CONFLICT (action_id) DO UPDATE SET
                    incident_id = EXCLUDED.incident_id,
                    action_type = EXCLUDED.action_type,
                    target_entity = EXCLUDED.target_entity,
                    decision = EXCLUDED.decision,
                    reviewer_name = EXCLUDED.reviewer_name,
                    reviewer_notes = EXCLUDED.reviewer_notes,
                    reviewed_at = EXCLUDED.reviewed_at,
                    execution_log = EXCLUDED.execution_log
                """,
                (
                    action["action_id"],
                    action["incident_id"],
                    action["action_type"],
                    action["target_entity"],
                    decision,
                    payload.reviewer_name.strip(),
                    payload.reviewer_notes.strip(),
                    Jsonb(execution_log),
                ),
            )
        return {"status": "saved", "decision": decision, "execution_log": execution_log}
    except HTTPException:
        raise
    except psycopg.Error as error:
        raise HTTPException(
            status_code=503, detail="Could not save the admin decision to Postgres."
        ) from error
    except Exception as error:
        raise HTTPException(
            status_code=500, detail="Could not process the admin decision."
        ) from error


@app.exception_handler(HTTPException)
async def api_error_handler(request: Request, error: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={"detail": error.detail},
        headers=error.headers,
    )


app.frontend("/", directory=str(ROOT / "public"), fallback="index.html")
