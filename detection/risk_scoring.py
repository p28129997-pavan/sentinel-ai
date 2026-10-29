from typing import Dict, Any, List

class RiskScorer:
    """
    Computes an explainable, deterministic risk score (0 - 100)
    for security incidents based on rule severity, source correlation diversity,
    sequence progression completeness, and evidence reliability.
    """

    SEVERITY_BASE = {
        "CRITICAL": 60.0,
        "HIGH": 45.0,
        "MEDIUM": 35.0,
        "LOW": 15.0
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        corr_cfg = self.config.get("rules", {}).get("correlation", {})
        self.two_sources_mult = corr_cfg.get("two_sources_multiplier", 1.25)
        self.three_sources_mult = corr_cfg.get("three_sources_multiplier", 1.5)
        self.seq_bonus = corr_cfg.get("sequence_match_bonus", 20.0)

    def calculate_score(
        self,
        triggered_rules: List[Dict[str, Any]],
        sources_involved: List[str],
        has_sequence_progression: bool,
        evidence_strength: float = 1.0, # 0.0 to 1.0
        unique_event_count: int = 1
    ) -> Dict[str, Any]:
        """
        Calculates explainable risk score and detailed factor breakdown.
        """
        if not triggered_rules:
            return {
                "score": 0.0,
                "category": "LOW",
                "confidence": 0.0,
                "factors": {
                    "base_severity": 0.0,
                    "rule_contribution": 0.0,
                    "source_multiplier": 1.0,
                    "sequence_bonus": 0.0,
                    "evidence_adjustment": 0.0
                },
                "summary": "No suspicious rules triggered."
            }

        # 1. Base Severity from highest triggered rule
        max_severity = "LOW"
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for r in triggered_rules:
            sev = r.get("severity", "LOW").upper()
            if severity_order.index(sev) > severity_order.index(max_severity):
                max_severity = sev

        base_score = self.SEVERITY_BASE.get(max_severity, 10.0)

        # 2. Cumulative rule contribution (sub-linear to prevent runaway score)
        # Unique rules only to prevent duplicate inflation
        seen_rules = set()
        secondary_points = 0.0
        for r in triggered_rules:
            rid = r.get("rule_id")
            if rid not in seen_rules:
                seen_rules.add(rid)
                bw = float(r.get("base_weight", 15.0))
                # Secondary rules add partial weight
                secondary_points += (bw * 0.25)
        # Cap secondary rule contribution
        secondary_points = min(secondary_points, 25.0)

        raw_subtotal = base_score + secondary_points

        # 3. Source Correlation Multiplier
        # Single source = 1.0x, Two sources = 1.25x, Three sources = 1.5x
        num_sources = len(set(sources_involved))
        if num_sources >= 3:
            source_mult = self.three_sources_mult
        elif num_sources == 2:
            source_mult = self.two_sources_mult
        else:
            source_mult = 1.0

        multiplied_score = raw_subtotal * source_mult

        # 4. Sequence Progression Bonus (e.g. Initial Access -> Credential -> C2)
        sequence_bonus = self.seq_bonus if has_sequence_progression else 0.0

        # 5. Evidence Reliability Adjustment
        # If evidence reliability is high (e.g. shared IP/Device), bonus; if ambiguous, slight penalty
        evidence_adjustment = (evidence_strength - 0.75) * 15.0

        # Total calculated score
        calculated = multiplied_score + sequence_bonus + evidence_adjustment

        # Bounding strictly to [0.0, 100.0]
        final_score = max(0.0, min(100.0, round(calculated, 1)))

        # Risk Category
        if final_score >= 85.0:
            category = "CRITICAL"
        elif final_score >= 70.0:
            category = "HIGH"
        elif final_score >= 40.0:
            category = "MEDIUM"
        else:
            category = "LOW"

        # Confidence (evidence completeness and source coverage)
        confidence = round(min(0.98, max(0.40, (0.4 * num_sources / 3.0) + (0.4 * evidence_strength) + (0.18 if has_sequence_progression else 0.0))), 2)

        return {
            "score": final_score,
            "category": category,
            "confidence": confidence,
            "factors": {
                "base_severity_rule": max_severity,
                "base_severity_points": round(base_score, 1),
                "additional_rules_points": round(secondary_points, 1),
                "sources_detected_count": num_sources,
                "correlation_multiplier": source_mult,
                "sequence_attack_chain_bonus": sequence_bonus,
                "evidence_reliability_adjustment": round(evidence_adjustment, 1)
            },
            "summary": f"Calculated {category} risk ({final_score}/100) across {num_sources} correlated data source(s)."
        }
