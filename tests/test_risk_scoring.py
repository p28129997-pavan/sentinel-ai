import pytest
from detection.risk_scoring import RiskScorer

@pytest.fixture
def risk_scorer():
    return RiskScorer()

def test_risk_score_bounds_zero_to_hundred(risk_scorer):
    # Empty rules
    low_res = risk_scorer.calculate_score([], [], False)
    assert 0.0 <= low_res["score"] <= 100.0
    assert low_res["score"] == 0.0
    assert low_res["category"] == "LOW"

    # Extreme high severity rules with multipliers
    extreme_rules = [
        {"rule_id": f"R{i}", "severity": "CRITICAL", "base_weight": 50}
        for i in range(10)
    ]
    high_res = risk_scorer.calculate_score(
        triggered_rules=extreme_rules,
        sources_involved=["EMAIL", "AUTH", "NETWORK"],
        has_sequence_progression=True,
        evidence_strength=1.0,
        unique_event_count=20
    )
    assert 0.0 <= high_res["score"] <= 100.0
    assert high_res["score"] == 100.0
    assert high_res["category"] == "CRITICAL"

def test_risk_score_categories(risk_scorer):
    res_low = risk_scorer.calculate_score([{"rule_id": "R1", "severity": "LOW", "base_weight": 10}], ["EMAIL"], False)
    assert res_low["category"] == "LOW"

    res_med = risk_scorer.calculate_score([{"rule_id": "R1", "severity": "MEDIUM", "base_weight": 35}], ["EMAIL"], False)
    assert res_med["category"] == "MEDIUM"

    res_crit = risk_scorer.calculate_score([
        {"rule_id": "R1", "severity": "CRITICAL", "base_weight": 50},
        {"rule_id": "R2", "severity": "HIGH", "base_weight": 40}
    ], ["EMAIL", "AUTH", "NETWORK"], True)
    assert res_crit["category"] == "CRITICAL"

def test_explainability_factors_present(risk_scorer):
    res = risk_scorer.calculate_score([
        {"rule_id": "R_BURST", "severity": "HIGH", "base_weight": 35}
    ], ["AUTH"], False)

    assert "factors" in res
    factors = res["factors"]
    assert "base_severity_points" in factors
    assert "correlation_multiplier" in factors
    assert "sequence_attack_chain_bonus" in factors
    assert "evidence_reliability_adjustment" in factors
