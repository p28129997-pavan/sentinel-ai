import json
from database.db import get_all_incidents, get_all_approvals
from response.sandbox import SimulationSandbox
from pipeline import run_detection_pipeline

def run_terminal_demo():
    print("\n" + "="*75)
    print("   SENTINEL AI -- Live Threat Investigation & Incident Triage")
    print("="*75)

    # 1. Ensure pipeline is fresh
    print("\n>>> [STEP 1] Ingesting Telemetry & Running Multi-Source Correlation Engine...")
    res = run_detection_pipeline()
    incidents = res["incidents"]
    print(f"    [OK] Processed {res['total_events_processed']} logs across Email, Auth, and Network.")
    print(f"    [OK] Correlated {len(incidents)} security incidents.\n")

    # Pick Campaign Alpha as deep dive
    alpha = next((i for i in incidents if i["campaign_tag"] == "CAMPAIGN_ALPHA"), incidents[0])

    print("-" * 75)
    print(f">>> [STEP 2] Deep Dive Triage: {alpha['title']}")
    print("-" * 75)
    print(f"• Incident ID:        {alpha['incident_id']}")
    print(f"• Classification:     {alpha['severity']} (Score: {alpha['risk_score']}/100, Confidence: {int(alpha['confidence']*100)}%)")
    print(f"• Primary User:       {alpha['primary_user']}")
    print(f"• Target Workstation: {alpha['primary_device']}")
    print(f"• Adversary IP:       {alpha['primary_ip']}")
    print(f"• Attack Chain Match: {'CONFIRMED (Email -> Auth -> Net)' if alpha['evidence']['sequence_matched'] else 'PARTIAL'}")

    print("\n--- 1. OBSERVED FACTS (Verifiable Telemetry) ---")
    for fact in alpha["explanation"]["observed_facts"]:
        print(f"  [+] {fact}")

    print("\n--- 2. INFERRED RELATIONSHIPS (Analytic Deductions) ---")
    for inf in alpha["explanation"]["inferred_relationships"]:
        print(f"  [>] {inf}")

    print("\n--- 3. EXPLAINABLE RISK SCORE FACTORS ---")
    factors = alpha["evidence"]["factors"]
    print(f"  * Base Rule Severity:            +{factors.get('base_severity_points')} pts ({factors.get('base_severity_rule')})")
    print(f"  * Additional Rules Contribution: +{factors.get('additional_rules_points')} pts")
    print(f"  * Cross-Source Multiplier:       x{factors.get('correlation_multiplier')} ({factors.get('sources_detected_count')} sources)")
    print(f"  * Attack Sequence Bonus:         +{factors.get('sequence_attack_chain_bonus')} pts")
    print(f"  * Evidence Reliability Adj:      {factors.get('evidence_reliability_adjustment'):+} pts")
    print(f"  --------------------------------------------------")
    print(f"  * FINAL CALCULATED SCORE:        {alpha['risk_score']}/100 ({alpha['severity']})")

    # Containment Action Authorization
    print("\n" + "-" * 75)
    print(">>> [STEP 3] Human-in-the-Loop Approval & Response Simulation Sandbox")
    print("-" * 75)
    actions = alpha["recommended_actions"]
    print(f"Incident generated {len(actions)} containment recommendations:")
    for idx, act in enumerate(actions, 1):
        print(f"  [{idx}] {act['action_id']} | Type: {act['action_type']:15} | Target: {act['target_entity']}")
        print(f"      Description: {act['description']}")

    # Simulate authorization of the first action
    target_action = actions[0]
    print(f"\n[*] Simulating SOC Analyst Decision for action '{target_action['action_id']}'...")
    reviewer = "SecOps-Analyst-Sarah"
    note = "Authorized emergency credential revocation following confirmed exfiltration to 198.51.100.45."
    
    decision_result = SimulationSandbox.process_human_decision(
        action_id=target_action["action_id"],
        decision="APPROVE",
        reviewer_name=reviewer,
        reviewer_notes=note,
        action_type=target_action["action_type"],
        target_entity=target_action["target_entity"]
    )

    print(f"\n[+] Decision Status:      {decision_result['status']}")
    print(f"[+] Reviewer Identity:    {reviewer}")
    print(f"[+] Decision Note:        {note}")
    print(f"[+] Sandbox Disclaimer:   {decision_result['log']['disclaimer']}")
    print("\n[+] Mock Execution Protocol Details:")
    for detail in decision_result["log"]["details"]:
        print(f"    --> {detail}")

    # Verify SQLite Record
    print("\n" + "-" * 75)
    print(">>> [STEP 4] SQLite Database Audit Verification")
    print("-" * 75)
    approvals = get_all_approvals()
    audited = next((a for a in approvals if a["action_id"] == target_action["action_id"]), None)
    if audited:
        print(f"[OK] Record persisted in SQLite table 'approvals':")
        print(f"     Action ID:   {audited['action_id']}")
        print(f"     Status:      {audited['status']}")
        print(f"     Reviewer:    {audited['reviewer_name']}")
        print(f"     Reviewed At: {audited['reviewed_at']}")
        print(f"     Decision:    {audited['decision']}")

    print("\n" + "="*75)
    print(" [OK] DEMONSTRATION COMPLETE. DASHBOARD READY AT: http://localhost:8501")
    print("="*75 + "\n")

if __name__ == "__main__":
    run_terminal_demo()
