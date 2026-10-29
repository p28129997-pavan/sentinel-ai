import os
import json
import re
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "detection_rules.json")

def load_rule_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    path = config_path or CONFIG_PATH
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

class URLAnalyzer:
    """
    Analyzes arbitrary random links/URLs for phishing patterns, high-risk TLDs,
    credential harvesting paths, typosquatting, and protocol anomalies.
    """
    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".buzz", ".live", ".fit", ".ru", ".cc", ".tk", ".ml", ".ga",
        ".cf", ".gq", ".work", ".click", ".icu", ".link", ".online", ".site", ".pw"
    }
    PHISHING_KEYWORDS = [
        "login", "signin", "verify", "credential", "account", "update", "banking",
        "secure", "wallet", "reset", "password", "billing", "invoice", "bonus",
        "auth", "token", "support", "helpdesk", "renewal", "payroll"
    ]
    TYPOSQUAT_PATTERNS = [
        ("paypa1", "PayPal lookalike"),
        ("micros0ft", "Microsoft lookalike"),
        ("goog1e", "Google lookalike"),
        ("app1e", "Apple lookalike"),
        ("amaz0n", "Amazon lookalike"),
        ("netf1ix", "Netflix lookalike"),
        ("0kta", "Okta lookalike"),
        ("c0rp", "Corporate lookalike")
    ]

    @classmethod
    def analyze_url(cls, url_str: str) -> Dict[str, Any]:
        findings = []
        risk_score = 0
        raw_url = (url_str or "").strip()
        if not raw_url:
            return {"url": "", "risk_score": 0, "verdict": "BENIGN / SAFE", "findings": ["Empty URL"]}

        if not raw_url.startswith(("http://", "https://")):
            raw_url = "http://" + raw_url

        try:
            parsed = urlparse(raw_url)
            hostname = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            full_url = raw_url.lower()
        except Exception:
            return {"url": url_str, "risk_score": 50, "verdict": "SUSPICIOUS", "findings": ["Malformed URL syntax"]}

        # Check 1: IP address as hostname (common in C2 and phishing)
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, hostname):
            findings.append(f"Host uses raw numeric IP address instead of domain: {hostname}")
            risk_score += 35

        # Check 2: High-risk TLD
        matched_tld = [tld for tld in cls.SUSPICIOUS_TLDS if hostname.endswith(tld)]
        if matched_tld:
            findings.append(f"High-risk untrusted top-level domain: {matched_tld[0]}")
            risk_score += 30

        # Check 3: Typosquatting / Brand Spoofing
        for spoof, desc in cls.TYPOSQUAT_PATTERNS:
            if spoof in hostname:
                findings.append(f"Typosquatting/brand spoofing detected: {desc} ('{spoof}')")
                risk_score += 40

        # Check 4: Phishing keywords in URL / path
        matched_kws = [kw for kw in cls.PHISHING_KEYWORDS if kw in full_url]
        if matched_kws:
            findings.append(f"Social engineering / credential harvesting keywords: {', '.join(matched_kws[:4])}")
            risk_score += min(len(matched_kws) * 15, 35)

        # Check 5: Insecure HTTP protocol
        if raw_url.startswith("http://"):
            findings.append("Insecure plain HTTP protocol (lacks TLS encryption)")
            risk_score += 10

        # Check 6: Non-standard web ports
        if parsed.port and parsed.port not in [80, 443]:
            findings.append(f"Non-standard web port in URL: :{parsed.port}")
            risk_score += 25

        # Check 7: Suspicious URL structure
        if "@" in raw_url:
            findings.append("URL contains '@' symbol (user-info obfuscation technique)")
            risk_score += 35
        if hostname.count(".") >= 4:
            findings.append(f"Excessive subdomain depth ({hostname.count('.')} levels)")
            risk_score += 15

        risk_score = min(100, risk_score)
        if risk_score >= 70:
            verdict = "MALICIOUS / PHISHING"
        elif risk_score >= 35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN / SAFE"

        return {
            "url": url_str,
            "normalized_url": raw_url,
            "hostname": hostname,
            "risk_score": risk_score,
            "verdict": verdict,
            "findings": findings
        }

class NetworkAnalyzer:
    """
    Analyzes arbitrary network flows and connections for known C2 ports,
    data exfiltration thresholds, beaconing patterns, and destination IP risk.
    """
    KNOWN_C2_PORTS = {
        4444: "Metasploit / Reverse Shell Default",
        8888: "HTTP Proxy / Generic C2 Port",
        1337: "Custom Backdoor / Leet Port",
        6667: "IRC Botnet Protocol",
        9001: "Tor Relay / Cobalt Strike Listener",
        8443: "Encrypted Staging / Alternate SSL C2",
        31337: "BackOrifice / Elite Trojan Port"
    }
    EXFILTRATION_THRESHOLD_BYTES = 50000000  # 50 MB

    @classmethod
    def analyze_flow(
        cls,
        dst_ip: str,
        dst_port: int,
        bytes_sent: int = 0,
        src_ip: str = "10.0.1.15",
        protocol: str = "TCP",
        dst_domain: str = "",
        is_beacon: bool = False
    ) -> Dict[str, Any]:
        findings = []
        risk_score = 0
        try:
            dst_port = int(dst_port)
        except Exception:
            dst_port = 80
        try:
            bytes_sent = int(bytes_sent)
        except Exception:
            bytes_sent = 0

        dst_ip = str(dst_ip).strip()
        mb_sent = round(bytes_sent / (1024 * 1024), 2)
        is_internal = (src_ip.startswith("10.") or src_ip.startswith("192.168.")) and (dst_ip.startswith("10.") or dst_ip.startswith("192.168."))

        # Check 1: Known C2 Port
        if dst_port in cls.KNOWN_C2_PORTS:
            desc = cls.KNOWN_C2_PORTS[dst_port]
            findings.append(f"Outbound connection on known C2 port {dst_port} ({desc})")
            risk_score += 45

        # Check 2: High volume data exfiltration
        if bytes_sent >= cls.EXFILTRATION_THRESHOLD_BYTES and not is_internal:
            findings.append(f"High-volume data exfiltration: {mb_sent} MB transferred outbound (threshold: 50 MB)")
            risk_score += 50
        elif bytes_sent >= 10000000 and not is_internal:
            findings.append(f"Elevated outbound data volume: {mb_sent} MB transferred")
            risk_score += 20

        # Check 3: C2 Beaconing
        if is_beacon or (bytes_sent > 0 and bytes_sent < 500 and dst_port in [4444, 8888, 9001, 8443]):
            findings.append("Periodic heartbeat beaconing pattern (repeated small payload sessions)")
            risk_score += 35

        # Check 4: Destination IP classification
        if is_internal:
            findings.append(f"Internal RFC1918 traffic ({src_ip} -> {dst_ip}) - lower perimeter risk")
        else:
            findings.append(f"External routable destination IP ({dst_ip})")

        # Check 5: Suspicious C2 Domain
        if dst_domain:
            tld_check = any(dst_domain.endswith(tld) for tld in [".xyz", ".top", ".buzz", ".ru", ".cc"])
            if tld_check:
                findings.append(f"Egress to suspicious TLD domain: {dst_domain}")
                risk_score += 25

        risk_score = min(100, risk_score)
        if risk_score >= 70:
            verdict = "CRITICAL / C2 MALICIOUS"
        elif risk_score >= 35:
            verdict = "SUSPICIOUS ACTIVITY"
        else:
            verdict = "BENIGN / NORMAL FLOW"

        return {
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "bytes_sent": bytes_sent,
            "mb_sent": mb_sent,
            "protocol": protocol,
            "dst_domain": dst_domain,
            "risk_score": risk_score,
            "verdict": verdict,
            "findings": findings
        }

class RuleEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_rule_config()
        self.email_rules = self.config.get("rules", {}).get("email", [])
        self.auth_rules = self.config.get("rules", {}).get("auth", [])
        self.net_rules = self.config.get("rules", {}).get("network", [])

    def evaluate_email_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluates an individual email gateway event against detection rules."""
        triggered = []
        subject = (event.get("subject") or "").lower()
        sender = (event.get("sender") or "").lower()
        attachments = event.get("attachments") or []
        spf = (event.get("spf_status") or "").upper()
        dkim = (event.get("dkim_status") or "").upper()
        dmarc = (event.get("dmarc_status") or "").upper()

        # Rule 1: Phishing keywords
        kw_rule = next((r for r in self.email_rules if r["id"] == "RULE_EMAIL_PHISHING_KEYWORD"), None)
        if kw_rule:
            matched_keywords = [kw for kw in kw_rule.get("keywords", []) if kw in subject]
            if matched_keywords:
                triggered.append({
                    "rule_id": kw_rule["id"],
                    "rule_name": kw_rule["name"],
                    "severity": kw_rule["severity"],
                    "base_weight": kw_rule["base_weight"],
                    "evidence": f"Subject matched social engineering keywords: {', '.join(matched_keywords)}"
                })

        # Rule 2: Suspicious sender domain or Auth Failures
        dom_rule = next((r for r in self.email_rules if r["id"] == "RULE_EMAIL_SUSPICIOUS_SENDER_DOMAIN"), None)
        if dom_rule:
            is_suspicious_tld = any(sender.endswith(tld) for tld in dom_rule.get("suspicious_tlds", []))
            is_suspicious_domain = any(d in sender for d in dom_rule.get("suspicious_domains", []))
            auth_failed = spf in ["FAIL", "SOFTFAIL"] or dkim == "FAIL" or dmarc == "FAIL"

            reasons = []
            if is_suspicious_tld or is_suspicious_domain:
                reasons.append(f"Untrusted sender domain '{sender}'")
            if auth_failed:
                reasons.append(f"Email authentication check failed (SPF={spf}, DKIM={dkim}, DMARC={dmarc})")

            if reasons:
                triggered.append({
                    "rule_id": dom_rule["id"],
                    "rule_name": dom_rule["name"],
                    "severity": dom_rule["severity"],
                    "base_weight": dom_rule["base_weight"],
                    "evidence": "; ".join(reasons)
                })

        # Rule 3: Malicious Attachment
        att_rule = next((r for r in self.email_rules if r["id"] == "RULE_EMAIL_MALICIOUS_ATTACHMENT"), None)
        if att_rule:
            risky_exts = att_rule.get("risky_extensions", [])
            flagged_attachments = [
                att for att in attachments
                if any(att.lower().endswith(ext) for ext in risky_exts)
            ]
            if flagged_attachments:
                triggered.append({
                    "rule_id": att_rule["id"],
                    "rule_name": att_rule["name"],
                    "severity": att_rule["severity"],
                    "base_weight": att_rule["base_weight"],
                    "evidence": f"Dangerous macro/executable attachments detected: {', '.join(flagged_attachments)}"
                })

        # Rule 4: Suspicious / Phishing URLs
        urls = event.get("urls") or []
        for u in urls:
            url_res = URLAnalyzer.analyze_url(u)
            if url_res["risk_score"] >= 35:
                triggered.append({
                    "rule_id": "RULE_EMAIL_SUSPICIOUS_URL",
                    "rule_name": f"Suspicious URL Indicator ({url_res['verdict']})",
                    "severity": "HIGH" if url_res["risk_score"] >= 70 else "MEDIUM",
                    "base_weight": 35 if url_res["risk_score"] >= 70 else 20,
                    "evidence": f"URL '{u}': {'; '.join(url_res['findings'])}"
                })

        return triggered

    def evaluate_auth_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluates authentication events for patterns such as failed bursts and impossible travel."""
        triggered = []
        if not events:
            return triggered

        # Sort chronologically
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

        # Rule 1: Failed Login Burst (e.g. >= 3 failures in short window)
        failed_count = sum(1 for e in sorted_events if e.get("auth_status") == "FAILURE")
        burst_rule = next((r for r in self.auth_rules if r["id"] == "RULE_AUTH_FAILED_BURST"), None)
        threshold = burst_rule.get("threshold_count", 3) if burst_rule else 3
        if burst_rule and failed_count >= threshold:
            triggered.append({
                "rule_id": burst_rule["id"],
                "rule_name": burst_rule["name"],
                "severity": burst_rule["severity"],
                "base_weight": burst_rule["base_weight"],
                "evidence": f"Detected {failed_count} authentication failures (threshold: {threshold})"
            })

        # Rule 2: Impossible travel / suspicious geolocation
        travel_rule = next((r for r in self.auth_rules if r["id"] == "RULE_AUTH_IMPOSSIBLE_TRAVEL"), None)
        locations = [e.get("location_country") for e in sorted_events if e.get("location_country")]
        distinct_countries = set(locations)
        if travel_rule and (len(distinct_countries) > 1 or "RU" in distinct_countries or "TOR" in distinct_countries):
            triggered.append({
                "rule_id": travel_rule["id"],
                "rule_name": travel_rule["name"],
                "severity": travel_rule["severity"],
                "base_weight": travel_rule["base_weight"],
                "evidence": f"Authentication attempts from geographically distant or high-risk locations: {', '.join(distinct_countries)}"
            })

        # Rule 3: MFA Fatigue / bypass
        mfa_rule = next((r for r in self.auth_rules if r["id"] == "RULE_AUTH_MFA_FATIGUE_BYPASS"), None)
        has_mfa_denials = any(e.get("failure_reason") == "MFA_PUSH_REJECTED" or e.get("mfa_status") == "DENIED" for e in sorted_events)
        has_subsequent_success = any(e.get("auth_status") == "SUCCESS" and e.get("mfa_status") in ["ACCEPTED_AFTER_DENIALS", "BYPASS_TOKEN"] for e in sorted_events)
        if mfa_rule and has_mfa_denials and has_subsequent_success:
            triggered.append({
                "rule_id": mfa_rule["id"],
                "rule_name": mfa_rule["name"],
                "severity": mfa_rule["severity"],
                "base_weight": mfa_rule["base_weight"],
                "evidence": "Repeated MFA push denials immediately succeeded by authentication acceptance (MFA Fatigue bypass pattern)."
            })

        # Rule 4: Privilege escalation / Service account abuse
        priv_rule = next((r for r in self.auth_rules if r["id"] == "RULE_AUTH_PRIVILEGE_ESCALATION"), None)
        if priv_rule:
            priv_users = priv_rule.get("privileged_users", [])
            for e in sorted_events:
                uid = e.get("user_id", "")
                auth_method = e.get("auth_method", "")
                if uid in priv_users or auth_method == "LOCAL_ADMIN_ELEVATION":
                    triggered.append({
                        "rule_id": priv_rule["id"],
                        "rule_name": priv_rule["name"],
                        "severity": priv_rule["severity"],
                        "base_weight": priv_rule["base_weight"],
                        "evidence": f"Unscheduled elevation or privileged account access: user '{uid}' via method '{auth_method}' on device '{e.get('device_id')}'"
                    })
                    break

        return triggered

    def evaluate_network_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluates network flow events for C2 ports, exfiltration volume, and beaconing."""
        triggered = []
        if not events:
            return triggered

        # Rule 1: Suspicious C2 Port
        port_rule = next((r for r in self.net_rules if r["id"] == "RULE_NET_SUSPICIOUS_C2_PORT"), None)
        if port_rule:
            susp_ports = port_rule.get("suspicious_ports", [])
            matched_events = [e for e in events if e.get("dst_port") in susp_ports]
            if matched_events:
                ports_str = ", ".join(str(e.get("dst_port")) for e in matched_events)
                ips_str = ", ".join(str(e.get("dst_ip")) for e in matched_events)
                triggered.append({
                    "rule_id": port_rule["id"],
                    "rule_name": port_rule["name"],
                    "severity": port_rule["severity"],
                    "base_weight": port_rule["base_weight"],
                    "evidence": f"Outbound connections to known C2 port(s) {ports_str} at destination IP(s) {ips_str}"
                })

        # Rule 2: High volume exfiltration
        vol_rule = next((r for r in self.net_rules if r["id"] == "RULE_NET_HIGH_VOLUME_EXFILTRATION"), None)
        if vol_rule:
            threshold = vol_rule.get("threshold_bytes", 50000000)
            exfil_events = [
                e for e in events
                if (e.get("bytes_sent") or 0) >= threshold
                # Exclude obvious benign internal backup patterns (e.g. 10.x to 10.x backup)
                and not (str(e.get("src_ip", "")).startswith("10.10.") and str(e.get("dst_ip", "")).startswith("10.10."))
            ]
            if exfil_events:
                total_bytes = sum(e.get("bytes_sent", 0) for e in exfil_events)
                mb = round(total_bytes / (1024 * 1024), 2)
                triggered.append({
                    "rule_id": vol_rule["id"],
                    "rule_name": vol_rule["name"],
                    "severity": vol_rule["severity"],
                    "base_weight": vol_rule["base_weight"],
                    "evidence": f"High-volume data transfer: {mb} MB exfiltrated outbound across {len(exfil_events)} session(s)"
                })

        # Rule 3: Beaconing Pattern
        beacon_rule = next((r for r in self.net_rules if r["id"] == "RULE_NET_BEACONING_PATTERN"), None)
        if beacon_rule and len(events) >= 3:
            # Check for repeated small payloads to same external dst_ip
            dst_groups = {}
            for e in events:
                dst = e.get("dst_ip")
                if dst:
                    dst_groups.setdefault(dst, []).append(e)
            for dst, group in dst_groups.items():
                if len(group) >= 3:
                    bytes_list = [g.get("bytes_sent", 0) for g in group]
                    if all(b < 500 for b in bytes_list):  # Small heartbeat packets
                        triggered.append({
                            "rule_id": beacon_rule["id"],
                            "rule_name": beacon_rule["name"],
                            "severity": beacon_rule["severity"],
                            "base_weight": beacon_rule["base_weight"],
                            "evidence": f"Periodic network beaconing detected: {len(group)} regular small-payload outbound sessions to {dst}"
                        })
                        break

        return triggered
