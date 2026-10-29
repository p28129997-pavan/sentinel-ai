import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from database.db import record_approval_decision

class SimulationSandbox:
    """
    Safety-first response simulation framework.
    Guarantees NO live commands, firewall updates, or account changes are executed.
    All actions are mock-executed within this isolated sandbox audit log.
    """

    SIMULATION_DISCLAIMER = (
        "SAFE SIMULATION MODE ACTIVE: No actual modifications will be executed "
        "against production directory services, endpoints, or perimeter firewalls."
    )

    @classmethod
    def execute_simulated_action(
        cls,
        action_type: str,
        target_entity: str,
        reviewer_name: str,
        reviewer_notes: str
    ) -> Dict[str, Any]:
        """
        Executes a mock response workflow and returns structured telemetry.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        if action_type == "REVOKE_SESSION":
            log = {
                "engine": "SENTINEL-SIMULATOR-v1.0",
                "action": "REVOKE_SESSION",
                "target": target_entity,
                "status": "SIMULATED_SUCCESS",
                "timestamp": now_iso,
                "disclaimer": cls.SIMULATION_DISCLAIMER,
                "mock_protocol": "OIDC / SAML Session Invalidation API",
                "details": [
                    f"Mock API Call: POST /api/v2/users/{target_entity}/tokens/revoke",
                    f"Simulated Response: HTTP 200 OK (Revoked 3 active JWT refresh tokens)",
                    f"Simulated Policy: User '{target_entity}' flagged for mandatory step-up authentication at next login."
                ]
            }
        elif action_type == "ISOLATE_DEVICE":
            log = {
                "engine": "SENTINEL-SIMULATOR-v1.0",
                "action": "ISOLATE_DEVICE",
                "target": target_entity,
                "status": "SIMULATED_SUCCESS",
                "timestamp": now_iso,
                "disclaimer": cls.SIMULATION_DISCLAIMER,
                "mock_protocol": "EDR Host Containment Gateway",
                "details": [
                    f"Mock API Call: POST /edr/devices/{target_entity}/contain",
                    f"Simulated Response: HTTP 200 OK (Local network firewall rules applied)",
                    f"Simulated Policy: Host '{target_entity}' restricted strictly to SOC telemetry port 443; egress severed."
                ]
            }
        elif action_type == "BLOCK_INDICATOR":
            log = {
                "engine": "SENTINEL-SIMULATOR-v1.0",
                "action": "BLOCK_INDICATOR",
                "target": target_entity,
                "status": "SIMULATED_SUCCESS",
                "timestamp": now_iso,
                "disclaimer": cls.SIMULATION_DISCLAIMER,
                "mock_protocol": "Next-Gen Firewall Threat Intelligence Ingestion API",
                "details": [
                    f"Mock API Call: POST /firewall/dynamic-lists/c2-blocklist/entries",
                    f"Payload: {{'indicator': '{target_entity}', 'ttl': 86400, 'action': 'DROP_SILENTLY'}}",
                    f"Simulated Response: HTTP 201 Created (Rule synchronized across 4 perimeter edge clusters)."
                ]
            }
        else:
            log = {
                "engine": "SENTINEL-SIMULATOR-v1.0",
                "action": action_type,
                "target": target_entity,
                "status": "SIMULATED_SUCCESS",
                "timestamp": now_iso,
                "disclaimer": cls.SIMULATION_DISCLAIMER,
                "details": [f"Simulated generic containment for entity '{target_entity}'."]
            }

        return log

    @classmethod
    def process_human_decision(
        cls,
        action_id: str,
        decision: str, # "APPROVE" or "REJECT"
        reviewer_name: str,
        reviewer_notes: str,
        action_type: str,
        target_entity: str,
        db_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Coordinates human reviewer authorization and updates the SQLite record.
        """
        if decision == "APPROVE":
            exec_log = cls.execute_simulated_action(
                action_type=action_type,
                target_entity=target_entity,
                reviewer_name=reviewer_name,
                reviewer_notes=reviewer_notes
            )
        else:
            now_iso = datetime.now(timezone.utc).isoformat()
            exec_log = {
                "engine": "SENTINEL-SIMULATOR-v1.0",
                "action": action_type,
                "target": target_entity,
                "status": "REJECTED_BY_OPERATOR",
                "timestamp": now_iso,
                "disclaimer": cls.SIMULATION_DISCLAIMER,
                "details": [
                    f"Action rejected by reviewer '{reviewer_name}'.",
                    f"Reason for rejection: {reviewer_notes}",
                    "Containment action cancelled; no changes simulated."
                ]
            }

        # Persist in SQLite
        success = record_approval_decision(
            action_id=action_id,
            decision=decision,
            reviewer_name=reviewer_name,
            reviewer_notes=reviewer_notes,
            execution_log=exec_log,
            db_path=db_path
        )

        return {
            "success": success,
            "status": "SIMULATED_EXECUTED" if decision == "APPROVE" else "REJECTED",
            "log": exec_log
        }
