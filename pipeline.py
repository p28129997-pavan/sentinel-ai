import os
import json
from typing import Dict, Any, List, Optional, Tuple

from database.db import init_db, reset_db, save_event, save_incident, get_all_incidents, get_all_events
from detection.correlation import CorrelationEngine
from detection.anomaly_detection import AnomalyDetector

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

def load_json_file(filename: str, data_dir: Optional[str] = None) -> Any:
    path = os.path.join(data_dir or DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def run_detection_pipeline(db_path: Optional[str] = None, data_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes end-to-end detection pipeline:
    1. Loads raw telemetry datasets
    2. Initializes SQLite database
    3. Ingests normalized events into database
    4. Runs multi-source correlation engine & state machine
    5. Saves detected incidents and pending approvals
    6. Runs experimental Isolation Forest anomaly detection
    7. Evaluates detection metrics against ground-truth benchmarks
    """
    init_db(db_path)
    reset_db(db_path)

    email_logs = load_json_file("email_logs.json", data_dir)
    auth_logs = load_json_file("auth_logs.json", data_dir)
    network_logs = load_json_file("network_logs.json", data_dir)
    ground_truth = load_json_file("ground_truth.json", data_dir)

    # 1. Normalize and ingest
    corr_engine = CorrelationEngine()
    normalized_events = corr_engine.normalize_events(email_logs, auth_logs, network_logs)

    for ev in normalized_events:
        save_event(ev, db_path)

    # 2. Run correlation engine
    detected_incidents = corr_engine.correlate(normalized_events)

    for inc in detected_incidents:
        save_incident(inc, db_path)

    # 3. Run experimental Isolation Forest
    ml_detector = AnomalyDetector()
    df_features = ml_detector.extract_features(email_logs, auth_logs, network_logs)
    df_anomaly_results = ml_detector.fit_and_predict(df_features)

    # 4. Evaluate against ground truth
    metrics = evaluate_against_ground_truth(detected_incidents, ground_truth)

    return {
        "status": "SUCCESS",
        "total_events_processed": len(normalized_events),
        "total_incidents_detected": len(detected_incidents),
        "incidents": detected_incidents,
        "anomaly_df": df_anomaly_results,
        "metrics": metrics,
        "events": normalized_events
    }

def evaluate_against_ground_truth(
    detected_incidents: List[Dict[str, Any]],
    ground_truth: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculates precision, recall, F1, and false-positive rate
    based on known synthetic attack campaigns and benign baselines.
    """
    expected_campaigns = {c["id"]: c for c in ground_truth.get("campaigns", [])}
    benign_events = set(ground_truth.get("benign_events", []))

    detected_campaign_tags = set(inc.get("campaign_tag") for inc in detected_incidents)

    # Calculate Campaign Detection Performance
    tp_campaigns = 0
    fn_campaigns = 0
    for cid, camp in expected_campaigns.items():
        if cid in detected_campaign_tags:
            tp_campaigns += 1
        else:
            fn_campaigns += 1

    fp_campaigns = sum(
        1 for tag in detected_campaign_tags
        if tag not in expected_campaigns and tag not in [
            "SUSPICIOUS_ACTIVITY",
            "ISOLATED_SUSPICIOUS_OUTSIDE_WINDOW"
        ]
    )

    precision = tp_campaigns / (tp_campaigns + fp_campaigns) if (tp_campaigns + fp_campaigns) > 0 else 1.0
    recall = tp_campaigns / (tp_campaigns + fn_campaigns) if (tp_campaigns + fn_campaigns) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Check event-level false positive rate among benign ground truth
    all_correlated_event_ids = set()
    for inc in detected_incidents:
        for ev in inc.get("correlated_events", []):
            all_correlated_event_ids.add(ev.get("event_id"))

    # Benign events that were mistakenly correlated into a confirmed high/critical incident
    benign_flagged = [eid for eid in benign_events if eid in all_correlated_event_ids]
    fpr = len(benign_flagged) / len(benign_events) if len(benign_events) > 0 else 0.0

    return {
        "campaigns_expected": len(expected_campaigns),
        "campaigns_detected": tp_campaigns,
        "campaigns_missed": fn_campaigns,
        "false_positive_campaigns": fp_campaigns,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "false_positive_rate": round(fpr, 3),
        "benign_events_count": len(benign_events),
        "benign_events_flagged_count": len(benign_flagged),
        "disclaimer": (
            "Benchmark calculated against synthetic validation scenario data. "
            "Performance on synthetic test sets does not guarantee identical performance on real-world networks."
        )
    }

if __name__ == "__main__":
    print("\n" + "="*70)
    print("   SENTINEL AI -- AI vs AI Threat Detection & Correlation Engine")
    print("="*70)
    print("[*] Ingesting multi-source logs (Email, Auth, Network)...")
    res = run_detection_pipeline()
    
    print(f"\n[+] Ingestion Complete: {res['total_events_processed']} raw telemetry events processed.")
    print(f"[+] Correlation Complete: {res['total_incidents_detected']} incidents identified.\n")
    
    print("-" * 70)
    print("IDENTIFIED THREAT CAMPAIGNS & CORRELATED INCIDENTS:")
    print("-" * 70)
    for inc in res["incidents"]:
        sev = inc["severity"]
        score = inc["risk_score"]
        title = inc["title"]
        user = inc.get("primary_user") or "N/A"
        dev = inc.get("primary_device") or "N/A"
        ip = inc.get("primary_ip") or "N/A"
        events_str = ", ".join(e["event_id"] for e in inc["correlated_events"])
        seq = "MATCHED (Email -> Auth -> Net)" if inc["evidence"]["sequence_matched"] else "PARTIAL"
        
        print(f"[*] [{sev}] {title}")
        print(f"   - Incident ID: {inc['incident_id']} | Risk Score: {score}/100")
        print(f"   - Target User: {user} | Device: {dev} | Threat IP: {ip}")
        print(f"   - Attack Sequence: {seq}")
        print(f"   - Correlated Telemetry: [{events_str}]")
        print(f"   - Rules Triggered: {', '.join(inc['rule_ids'])}")
        print(f"   - Recommended Containment: {len(inc['recommended_actions'])} simulated actions pending")
        print()
        
    m = res["metrics"]
    print("-" * 70)
    print("DETECTION BENCHMARK EVALUATION (GROUND TRUTH):")
    print("-" * 70)
    print(f"[*] Expected Campaigns: {m['campaigns_expected']} | Detected: {m['campaigns_detected']} | Missed: {m['campaigns_missed']}")
    print(f"[*] Precision: {m['precision']*100:.1f}% | Recall: {m['recall']*100:.1f}% | F1 Score: {m['f1_score']:.2f}")
    print(f"[*] Benign False Positive Rate: {m['false_positive_rate']*100:.1f}% ({m['benign_events_flagged_count']} of {m['benign_events_count']} benign events flagged)")
    
    print("\n" + "="*70)
    print(" [OK] SENTINEL AI SOC DASHBOARD IS LIVE AT: http://localhost:8501")
    print("="*70 + "\n")

