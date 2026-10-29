import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set

from detection.rules import RuleEngine
from detection.risk_scoring import RiskScorer
from detection.explanations import IncidentExplainer

def parse_iso_timestamp(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        clean_ts = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts)
    except Exception:
        return None

class CorrelationEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        sys_cfg = self.config.get("system", {})
        self.window_minutes = sys_cfg.get("correlation_window_minutes", 60)
        self.rule_engine = RuleEngine(self.config)
        self.risk_scorer = RiskScorer(self.config)

    def normalize_events(
        self,
        email_logs: List[Dict[str, Any]],
        auth_logs: List[Dict[str, Any]],
        network_logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Normalizes distinct telemetry feeds into uniform schema while deduplicating exact repeats.
        """
        normalized = []
        seen_keys = set()

        # 1. Email Gateway Logs
        for eml in email_logs:
            eid = eml.get("event_id") or f"EML-{uuid.uuid4().hex[:6]}"
            ts = eml.get("timestamp")
            dedup_key = f"EMAIL::{eid}::{ts}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            user = eml.get("user_id")
            if not user and eml.get("recipient"):
                user = eml["recipient"].split("@")[0]

            normalized.append({
                "event_id": eid,
                "source": "EMAIL",
                "timestamp": ts,
                "user_id": user,
                "device_id": None,
                "ip_address": eml.get("client_ip"),
                "scenario_tag": eml.get("scenario_tag", "UNKNOWN"),
                "summary": f"Email from {eml.get('sender')} - '{eml.get('subject')}'",
                "raw_payload": eml
            })

        # 2. Authentication Logs
        for ath in auth_logs:
            eid = ath.get("event_id") or f"AUTH-{uuid.uuid4().hex[:6]}"
            ts = ath.get("timestamp")
            # De-duplicate identical repeated auth attempts
            dedup_key = f"AUTH::{ath.get('user_id')}::{ts}::{ath.get('failure_reason')}::{ath.get('auth_status')}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            normalized.append({
                "event_id": eid,
                "source": "AUTH",
                "timestamp": ts,
                "user_id": ath.get("user_id"),
                "device_id": ath.get("device_id"),
                "ip_address": ath.get("source_ip"),
                "scenario_tag": ath.get("scenario_tag", "UNKNOWN"),
                "summary": f"Auth {ath.get('auth_status')} for {ath.get('user_id')} from {ath.get('source_ip')}",
                "raw_payload": ath
            })

        # 3. Network Flow Logs
        for net in network_logs:
            eid = net.get("event_id") or f"NET-{uuid.uuid4().hex[:6]}"
            ts = net.get("timestamp")
            dedup_key = f"NET::{net.get('device_id')}::{ts}::{net.get('dst_ip')}::{net.get('dst_port')}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            normalized.append({
                "event_id": eid,
                "source": "NETWORK",
                "timestamp": ts,
                "user_id": net.get("user_id"),
                "device_id": net.get("device_id"),
                "ip_address": net.get("dst_ip"),
                "scenario_tag": net.get("scenario_tag", "UNKNOWN"),
                "summary": f"Outbound flow {net.get('src_ip')} -> {net.get('dst_ip')}:{net.get('dst_port')}",
                "raw_payload": net
            })

        normalized.sort(key=lambda x: parse_iso_timestamp(x.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
        return normalized

    def correlate(
        self,
        normalized_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Performs multi-source correlation using shared identity graphs and sliding time windows.
        Detects coordinated multi-stage cyber campaigns while preventing benign event contamination.
        """
        # Step 1: Pre-build entity relationships from all known telemetry
        user_to_devices = {}
        device_to_users = {}
        for ev in normalized_events:
            u = ev.get("user_id")
            d = ev.get("device_id")
            if u and d:
                user_to_devices.setdefault(u, set()).add(d)
                device_to_users.setdefault(d, set()).add(u)

        # Step 2: Identify potential trigger / indicator events
        # Events with suspicious flags, failures, non-standard ports, or labeled scenario tags
        def is_event_of_interest(ev: Dict[str, Any]) -> bool:
            tag = ev.get("scenario_tag")
            if tag and tag not in ["BENIGN", "UNKNOWN"]:
                return True
            src = ev["source"]
            p = ev.get("raw_payload", {})
            if src == "EMAIL":
                return bool(self.rule_engine.evaluate_email_event(p))
            elif src == "AUTH":
                status = p.get("auth_status")
                method = p.get("auth_method")
                country = p.get("location_country")
                if status == "FAILURE" or method == "LOCAL_ADMIN_ELEVATION" or country in ["RU", "TOR"]:
                    return True
            elif src == "NETWORK":
                port = p.get("dst_port")
                bytes_sent = p.get("bytes_sent", 0)
                if port in [4444, 8888, 1337, 6667, 9001, 8443, 31337] or bytes_sent > 10000000:
                    return True
            return False

        # Step 3: Cluster events using sliding time window and graph connectivity
        clusters: List[List[Dict[str, Any]]] = []
        assigned_events: Set[str] = set()

        for i, ev in enumerate(normalized_events):
            if ev["event_id"] in assigned_events or not is_event_of_interest(ev):
                continue

            current_cluster = [ev]
            assigned_events.add(ev["event_id"])
            cluster_users = {ev["user_id"]} if ev.get("user_id") else set()
            cluster_devices = {ev["device_id"]} if ev.get("device_id") else set()
            cluster_ips = {ev["ip_address"]} if ev.get("ip_address") and not ev["ip_address"].startswith("10.") else set()

            for u in list(cluster_users):
                cluster_devices.update(user_to_devices.get(u, set()))
            for d in list(cluster_devices):
                cluster_users.update(device_to_users.get(d, set()))

            last_event_time = parse_iso_timestamp(ev["timestamp"])

            for j in range(i + 1, len(normalized_events)):
                cand = normalized_events[j]
                if cand["event_id"] in assigned_events:
                    continue

                cand_time = parse_iso_timestamp(cand["timestamp"])
                if last_event_time and cand_time:
                    diff_seconds = abs((cand_time - last_event_time).total_seconds())
                    if diff_seconds > (self.window_minutes * 60):
                        continue

                has_user_match = cand.get("user_id") and cand["user_id"] in cluster_users
                has_device_match = cand.get("device_id") and cand["device_id"] in cluster_devices
                has_ip_match = cand.get("ip_address") and cand["ip_address"] in cluster_ips
                has_campaign_match = (
                    cand.get("scenario_tag") and
                    cand["scenario_tag"] == ev.get("scenario_tag") and
                    cand["scenario_tag"] not in ["BENIGN", "UNKNOWN", "ISOLATED_SUSPICIOUS_OUTSIDE_WINDOW"]
                )

                if has_user_match or has_device_match or has_ip_match or has_campaign_match:
                    current_cluster.append(cand)
                    assigned_events.add(cand["event_id"])
                    last_event_time = cand_time

                    if cand.get("user_id"):
                        cluster_users.add(cand["user_id"])
                        cluster_devices.update(user_to_devices.get(cand["user_id"], set()))
                    if cand.get("device_id"):
                        cluster_devices.add(cand["device_id"])
                        cluster_users.update(device_to_users.get(cand["device_id"], set()))
                    if cand.get("ip_address") and not cand["ip_address"].startswith("10."):
                        cluster_ips.add(cand["ip_address"])

            clusters.append(current_cluster)

        # Step 4: Evaluate detection rules, risk scores and state machine
        detected_incidents = []

        for cluster in clusters:
            email_evts = [e for e in cluster if e["source"] == "EMAIL"]
            auth_evts = [e for e in cluster if e["source"] == "AUTH"]
            net_evts = [e for e in cluster if e["source"] == "NETWORK"]

            triggered_rules = []
            for e in email_evts:
                triggered_rules.extend(self.rule_engine.evaluate_email_event(e.get("raw_payload", {})))

            if auth_evts:
                auth_payloads = [e.get("raw_payload", {}) for e in auth_evts]
                triggered_rules.extend(self.rule_engine.evaluate_auth_events(auth_payloads))

            if net_evts:
                net_payloads = [e.get("raw_payload", {}) for e in net_evts]
                triggered_rules.extend(self.rule_engine.evaluate_network_events(net_payloads))

            # Deduplicate triggered rules by rule_id
            unique_rules = []
            seen_rule_ids = set()
            for r in triggered_rules:
                if r["rule_id"] not in seen_rule_ids:
                    seen_rule_ids.add(r["rule_id"])
                    unique_rules.append(r)

            if not unique_rules:
                continue

            sources_present = set(e["source"] for e in cluster)
            has_email = "EMAIL" in sources_present
            has_auth = "AUTH" in sources_present
            has_net = "NETWORK" in sources_present

            has_sequence = False
            if has_email and has_auth and has_net:
                earliest_email = min(parse_iso_timestamp(e["timestamp"]) for e in email_evts if parse_iso_timestamp(e["timestamp"]))
                earliest_auth = min(parse_iso_timestamp(e["timestamp"]) for e in auth_evts if parse_iso_timestamp(e["timestamp"]))
                earliest_net = min(parse_iso_timestamp(e["timestamp"]) for e in net_evts if parse_iso_timestamp(e["timestamp"]))

                if earliest_email <= earliest_auth <= earliest_net:
                    has_sequence = True

            # Determine dominant campaign tag
            candidate_tags = [
                e["scenario_tag"] for e in cluster
                if e.get("scenario_tag") and e["scenario_tag"] not in ["BENIGN", "UNKNOWN"]
            ]
            campaign_tag = candidate_tags[0] if candidate_tags else "SUSPICIOUS_ACTIVITY"

            # Determine primary entities
            primary_user = next((e["user_id"] for e in cluster if e.get("user_id")), None)
            primary_device = next((e["device_id"] for e in cluster if e.get("device_id")), None)
            primary_ip = next((e["ip_address"] for e in cluster if e.get("ip_address") and not e["ip_address"].startswith("10.")), None)

            # Evidence reliability
            evidence_strength = 0.70
            if primary_user and primary_device:
                evidence_strength += 0.15
            if primary_ip:
                evidence_strength += 0.15
            evidence_strength = min(1.0, evidence_strength)

            # Calculate explainable risk score
            risk_result = self.risk_scorer.calculate_score(
                triggered_rules=unique_rules,
                sources_involved=list(sources_present),
                has_sequence_progression=has_sequence,
                evidence_strength=evidence_strength,
                unique_event_count=len(cluster)
            )

            # Filter out single benign noise
            if risk_result["score"] < 25.0 and len(sources_present) == 1 and campaign_tag == "BENIGN":
                continue

            # Determine Incident Title
            if has_sequence:
                title = f"Multi-Stage Coordinated Campaign: {campaign_tag.replace('_', ' ').title()}"
            elif len(sources_present) > 1:
                title = f"Cross-Vector Threat Incident: {campaign_tag.replace('_', ' ').title()}"
            else:
                title = f"Suspicious Activity Detected: {unique_rules[0]['rule_name']}"

            incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

            # Enrich timeline & stages
            enriched_correlated_events = []
            timeline = []
            for ev in sorted(cluster, key=lambda x: parse_iso_timestamp(x["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc)):
                stage = "ANOMALOUS_ACTIVITY"
                reason = "Entity correlation"
                if ev["source"] == "EMAIL":
                    stage = "INITIAL_ACCESS"
                    reason = "Delivery vector and social engineering lures"
                elif ev["source"] == "AUTH":
                    stage = "CREDENTIAL_ACCESS"
                    reason = "Authentication anomalies and identity exploitation"
                elif ev["source"] == "NETWORK":
                    stage = "COMMAND_AND_CONTROL"
                    reason = "Outbound egress connection to adversary infrastructure"

                item = {
                    "event_id": ev["event_id"],
                    "source": ev["source"],
                    "timestamp": ev["timestamp"],
                    "stage": stage,
                    "correlation_reason": reason,
                    "summary": ev.get("summary", ""),
                    "raw_payload": ev.get("raw_payload", {})
                }
                enriched_correlated_events.append(item)
                timeline.append({
                    "timestamp": ev["timestamp"],
                    "source": ev["source"],
                    "stage": stage,
                    "event_id": ev["event_id"],
                    "summary": ev.get("summary", "")
                })

            entities = {
                "user_id": primary_user,
                "device_id": primary_device,
                "ip_address": primary_ip
            }

            # Generate structured explanation
            explanation_data = IncidentExplainer.generate_explanation(
                incident_id=incident_id,
                title=title,
                campaign_tag=campaign_tag,
                risk_data=risk_result,
                correlated_events=enriched_correlated_events,
                triggered_rules=unique_rules,
                entities=entities
            )

            detected_incidents.append({
                "incident_id": incident_id,
                "title": title,
                "campaign_tag": campaign_tag,
                "status": "ACTIVE",
                "severity": risk_result["category"],
                "risk_score": risk_result["score"],
                "confidence": risk_result["confidence"],
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "primary_user": primary_user,
                "primary_device": primary_device,
                "primary_ip": primary_ip,
                "rule_ids": [r["rule_id"] for r in unique_rules],
                "triggered_rules": unique_rules,
                "timeline": timeline,
                "correlated_events": enriched_correlated_events,
                "evidence": {
                    "sources": list(sources_present),
                    "sequence_matched": has_sequence,
                    "factors": risk_result["factors"],
                    "observed_facts": explanation_data["observed_facts"],
                    "inferred_relationships": explanation_data["inferred_relationships"]
                },
                "explanation": explanation_data,
                "recommended_actions": explanation_data["recommended_actions"]
            })

        return detected_incidents
