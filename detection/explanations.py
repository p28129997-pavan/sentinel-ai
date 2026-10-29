from typing import Dict, Any, List

class IncidentExplainer:
    """
    Generates structured, explainable security alerts clearly separating:
    1. Observed Facts (direct raw log evidence)
    2. Inferred Relationships (analytical correlation conclusions)
    3. Recommended Actions (safe, human-in-the-loop response recommendations)
    """

    @staticmethod
    def generate_explanation(
        incident_id: str,
        title: str,
        campaign_tag: str,
        risk_data: Dict[str, Any],
        correlated_events: List[Dict[str, Any]],
        triggered_rules: List[Dict[str, Any]],
        entities: Dict[str, Any]
    ) -> Dict[str, Any]:
        user = entities.get("user_id") or "Unknown User"
        device = entities.get("device_id") or "Unknown Device"
        indicator_ip = entities.get("ip_address") or "N/A"

        # 1. Observed Facts
        observed_facts = []
        for ev in correlated_events:
            src = ev.get("source", "EVENT")
            ts = ev.get("timestamp", "Unknown Time")
            eid = ev.get("event_id", "")
            raw = ev.get("raw_payload", {}) or {}

            if src == "EMAIL":
                subj = raw.get("subject", "N/A")
                sender = raw.get("sender", "N/A")
                spf = raw.get("spf_status", "N/A")
                observed_facts.append(
                    f"[{ts}] Email Gateway ({eid}): Inbound email from '{sender}' to '{user}' with subject '{subj}' (SPF={spf})."
                )
            elif src == "AUTH":
                status = raw.get("auth_status", "N/A")
                src_ip = raw.get("source_ip", "N/A")
                loc = f"{raw.get('location_city', '')}, {raw.get('location_country', '')}".strip(", ")
                observed_facts.append(
                    f"[{ts}] Authentication ({eid}): Auth attempt for user '{user}' from IP '{src_ip}' ({loc}) - Status: {status}."
                )
            elif src == "NETWORK":
                dst_ip = raw.get("dst_ip", "N/A")
                dst_port = raw.get("dst_port", "N/A")
                sent_bytes = raw.get("bytes_sent", 0)
                mb = round(sent_bytes / (1024 * 1024), 2)
                observed_facts.append(
                    f"[{ts}] Network Flow ({eid}): Outbound TCP traffic from device '{device}' to '{dst_ip}:{dst_port}' ({mb} MB transferred)."
                )

        # 2. Inferred Relationships
        inferred_relationships = []
        rule_names = [r.get("rule_name") for r in triggered_rules]

        if "RULE_EMAIL_PHISHING_KEYWORD" in [r.get("rule_id") for r in triggered_rules] or "RULE_EMAIL_MALICIOUS_ATTACHMENT" in [r.get("rule_id") for r in triggered_rules]:
            inferred_relationships.append(
                f"Initial Access Vector: User '{user}' was targeted via social engineering or weaponized attachment."
            )

        if any(r.get("rule_id") in ["RULE_AUTH_FAILED_BURST", "RULE_AUTH_IMPOSSIBLE_TRAVEL", "RULE_AUTH_MFA_FATIGUE_BYPASS", "RULE_AUTH_PRIVILEGE_ESCALATION"] for r in triggered_rules):
            inferred_relationships.append(
                f"Credential & Privilege Compromise: Suspicious authentication anomalies correlate directly with the preceding delivery vector on device '{device}'."
            )

        if any(r.get("rule_id") in ["RULE_NET_SUSPICIOUS_C2_PORT", "RULE_NET_HIGH_VOLUME_EXFILTRATION", "RULE_NET_BEACONING_PATTERN"] for r in triggered_rules):
            inferred_relationships.append(
                f"Command-and-Control / Exfiltration: Compromised endpoint established persistent communication and/or exfiltrated corporate data to external infrastructure {indicator_ip}."
            )

        inferred_relationships.append(
            f"Cross-Source Correlation: Identified temporal and entity causality connecting {len(correlated_events)} discrete events across email, identity, and network telemetry."
        )

        # 3. Recommended Containment Actions
        recommended_actions = []
        action_idx = 1

        if user and user != "Unknown User":
            recommended_actions.append({
                "action_id": f"ACT-{incident_id[:8]}-0{action_idx}",
                "action_type": "REVOKE_SESSION",
                "target_entity": user,
                "description": f"Simulate revoking active IdP/SSO session tokens and enforce mandatory credential reset for user '{user}'.",
                "risk_mitigation": "Immediately truncates attacker session persistence."
            })
            action_idx += 1

        if device and device != "Unknown Device":
            recommended_actions.append({
                "action_id": f"ACT-{incident_id[:8]}-0{action_idx}",
                "action_type": "ISOLATE_DEVICE",
                "target_entity": device,
                "description": f"Simulate host network isolation for endpoint '{device}' via EDR agent.",
                "risk_mitigation": "Halts lateral movement and ongoing data exfiltration while maintaining management telemetry."
            })
            action_idx += 1

        if indicator_ip and indicator_ip != "N/A" and not indicator_ip.startswith("10."):
            recommended_actions.append({
                "action_id": f"ACT-{incident_id[:8]}-0{action_idx}",
                "action_type": "BLOCK_INDICATOR",
                "target_entity": indicator_ip,
                "description": f"Simulate adding adversary IP '{indicator_ip}' and associated domains to perimeter edge firewall blocklist.",
                "risk_mitigation": "Denies egress C2 callback channels enterprise-wide."
            })

        # Narrative explanation markdown
        narrative = f"""### Incident Summary: {title}

**Risk Assessment**: `{risk_data.get('category')}` Risk Score: **{risk_data.get('score')}/100** (Confidence: {int(risk_data.get('confidence', 0)*100)}%)

#### 1. Observed Security Facts
{"".join(f"- {f}\n" for f in observed_facts)}

#### 2. Inferred Threat Relationships
{"".join(f"- {i}\n" for i in inferred_relationships)}

#### 3. Recommended Safe Containment Actions
{"".join(f"- **{a['action_type']}** on `{a['target_entity']}`: {a['description']}\n" for a in recommended_actions)}

> **Simulation Notice**: SENTINEL AI operates in safe simulation mode. No live production endpoints or firewall policies will be modified. All containment actions require explicit SOC reviewer authorization.
"""

        return {
            "narrative_markdown": narrative,
            "observed_facts": observed_facts,
            "inferred_relationships": inferred_relationships,
            "recommended_actions": recommended_actions
        }
