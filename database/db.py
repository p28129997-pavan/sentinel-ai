import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel.db")

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a database connection with dict-like row access."""
    path = db_path or DB_FILE_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: Optional[str] = None):
    """Initializes the SQLite schema."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        source TEXT NOT NULL, -- EMAIL, AUTH, NETWORK
        timestamp TEXT NOT NULL,
        user_id TEXT,
        device_id TEXT,
        ip_address TEXT,
        scenario_tag TEXT,
        summary TEXT,
        raw_payload TEXT,
        created_at TEXT NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        campaign_tag TEXT,
        status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, CONTAINED, CLOSED
        severity TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
        risk_score REAL NOT NULL,
        confidence REAL NOT NULL,
        detected_at TEXT NOT NULL,
        primary_user TEXT,
        primary_device TEXT,
        primary_ip TEXT,
        rule_ids TEXT, -- JSON array of triggered rule IDs
        timeline TEXT, -- JSON array of correlated timeline items
        evidence TEXT, -- JSON object of supporting facts & inferences
        explanation TEXT, -- JSON/Markdown explanation
        recommended_actions TEXT, -- JSON array of recommended containment actions
        created_at TEXT NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        source TEXT NOT NULL,
        stage TEXT NOT NULL, -- INITIAL_ACCESS, CREDENTIAL_ACCESS, C2_COMMUNICATION, EXFILTRATION, ANOMALOUS_ACTIVITY
        correlation_reason TEXT,
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE,
        FOREIGN KEY (event_id) REFERENCES events (event_id) ON DELETE CASCADE
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS approvals (
        action_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        action_type TEXT NOT NULL, -- REVOKE_SESSION, ISOLATE_DEVICE, BLOCK_INDICATOR
        target_entity TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL', -- PENDING_APPROVAL, APPROVED, REJECTED, SIMULATED_EXECUTED
        reviewer_name TEXT,
        decision TEXT, -- APPROVE, REJECT
        reviewer_notes TEXT,
        requested_at TEXT NOT NULL,
        reviewed_at TEXT,
        execution_log TEXT,
        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT
    );
    """)

    conn.commit()
    conn.close()

def reset_db(db_path: Optional[str] = None):
    """Clears all tables in the database for clean demo execution."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM incident_events;")
    cur.execute("DELETE FROM approvals;")
    cur.execute("DELETE FROM incidents;")
    cur.execute("DELETE FROM events;")
    cur.execute("DELETE FROM audit_logs;")
    conn.commit()
    conn.close()

def save_event(event: Dict[str, Any], db_path: Optional[str] = None):
    """Inserts or updates a normalized event in the events table."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    cur.execute("""
        INSERT OR REPLACE INTO events (
            event_id, source, timestamp, user_id, device_id, ip_address,
            scenario_tag, summary, raw_payload, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("event_id"),
        event.get("source"),
        event.get("timestamp"),
        event.get("user_id"),
        event.get("device_id"),
        event.get("ip_address"),
        event.get("scenario_tag"),
        event.get("summary", ""),
        json.dumps(event.get("raw_payload", {})),
        now_iso
    ))
    conn.commit()
    conn.close()

def get_all_events(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all events ordered chronologically."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY timestamp ASC")
    rows = cur.fetchall()
    events = []
    for r in rows:
        item = dict(r)
        if item.get("raw_payload"):
            try:
                item["raw_payload"] = json.loads(item["raw_payload"])
            except Exception:
                pass
        events.append(item)
    conn.close()
    return events

def save_incident(incident: Dict[str, Any], db_path: Optional[str] = None):
    """Saves a detected incident along with its correlated events and initial response actions."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute("""
        INSERT OR REPLACE INTO incidents (
            incident_id, title, campaign_tag, status, severity, risk_score,
            confidence, detected_at, primary_user, primary_device, primary_ip,
            rule_ids, timeline, evidence, explanation, recommended_actions, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident["incident_id"],
        incident.get("title", f"Threat Incident {incident['incident_id']}"),
        incident.get("campaign_tag"),
        incident.get("status", "ACTIVE"),
        incident.get("severity", "MEDIUM"),
        float(incident.get("risk_score", 0.0)),
        float(incident.get("confidence", 0.0)),
        incident.get("detected_at", now_iso),
        incident.get("primary_user"),
        incident.get("primary_device"),
        incident.get("primary_ip"),
        json.dumps(incident.get("rule_ids", [])),
        json.dumps(incident.get("timeline", [])),
        json.dumps(incident.get("evidence", {})),
        json.dumps(incident.get("explanation", {})),
        json.dumps(incident.get("recommended_actions", [])),
        now_iso
    ))

    # Save incident_events
    cur.execute("DELETE FROM incident_events WHERE incident_id = ?", (incident["incident_id"],))
    for ev in incident.get("correlated_events", []):
        cur.execute("""
            INSERT INTO incident_events (incident_id, event_id, source, stage, correlation_reason)
            VALUES (?, ?, ?, ?, ?)
        """, (
            incident["incident_id"],
            ev.get("event_id"),
            ev.get("source", "UNKNOWN"),
            ev.get("stage", "CORRELATED_STAGE"),
            ev.get("correlation_reason", "")
        ))

    # Initialize pending approvals if not already present
    for act in incident.get("recommended_actions", []):
        cur.execute("SELECT action_id FROM approvals WHERE action_id = ?", (act.get("action_id"),))
        existing = cur.fetchone()
        if not existing:
            cur.execute("""
                INSERT INTO approvals (
                    action_id, incident_id, action_type, target_entity,
                    description, status, requested_at
                ) VALUES (?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?)
            """, (
                act.get("action_id"),
                incident["incident_id"],
                act.get("action_type"),
                act.get("target_entity"),
                act.get("description", ""),
                now_iso
            ))

    conn.commit()
    conn.close()

def get_all_incidents(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all incidents ordered by risk score descending."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents ORDER BY risk_score DESC, detected_at DESC")
    rows = cur.fetchall()
    incidents = []
    for r in rows:
        item = dict(r)
        for json_field in ["rule_ids", "timeline", "evidence", "explanation", "recommended_actions"]:
            if item.get(json_field):
                try:
                    item[json_field] = json.loads(item[json_field])
                except Exception:
                    pass
        incidents.append(item)
    conn.close()
    return incidents

def get_incident_by_id(incident_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a single incident by its ID."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    item = dict(row)
    for json_field in ["rule_ids", "timeline", "evidence", "explanation", "recommended_actions"]:
        if item.get(json_field):
            try:
                item[json_field] = json.loads(item[json_field])
            except Exception:
                pass

    # Fetch correlated events
    cur.execute("SELECT * FROM incident_events WHERE incident_id = ?", (incident_id,))
    item["correlated_events"] = [dict(ev) for ev in cur.fetchall()]
    conn.close()
    return item

def get_all_approvals(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all response approvals."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM approvals ORDER BY requested_at DESC")
    rows = cur.fetchall()
    approvals = []
    for r in rows:
        item = dict(r)
        if item.get("execution_log"):
            try:
                item["execution_log"] = json.loads(item["execution_log"])
            except Exception:
                pass
        approvals.append(item)
    conn.close()
    return approvals

def record_approval_decision(
    action_id: str,
    decision: str,
    reviewer_name: str,
    reviewer_notes: str,
    execution_log: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None
) -> bool:
    """Updates approval status with decision, notes, timestamp and execution log."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    status = "SIMULATED_EXECUTED" if decision == "APPROVE" else "REJECTED"

    cur.execute("""
        UPDATE approvals
        SET status = ?,
            reviewer_name = ?,
            decision = ?,
            reviewer_notes = ?,
            reviewed_at = ?,
            execution_log = ?
        WHERE action_id = ?
    """, (
        status,
        reviewer_name,
        decision,
        reviewer_notes,
        now_iso,
        json.dumps(execution_log or {}),
        action_id
    ))
    updated = cur.rowcount > 0

    # Also log audit trail
    cur.execute("""
        INSERT INTO audit_logs (timestamp, action, details)
        VALUES (?, ?, ?)
    """, (
        now_iso,
        f"HUMAN_DECISION_{decision}",
        f"Action {action_id} reviewed by {reviewer_name}. Result: {status}. Note: {reviewer_notes}"
    ))

    conn.commit()
    conn.close()
    return updated
