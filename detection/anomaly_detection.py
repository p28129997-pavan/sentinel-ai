import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, List

class AnomalyDetector:
    """
    Experimental Isolation Forest anomaly detection for identity and endpoint telemetry.
    Note: Unsupervised anomaly detection flags mathematical outliers in feature space;
    it does NOT definitively establish a cyberattack or malicious intent without
    corroborating rule evidence and human analyst confirmation.
    """

    def __init__(self, contamination: float = 0.15, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100
        )
        self.feature_names = [
            "failed_login_count",
            "total_auth_count",
            "distinct_source_ips",
            "outbound_bytes_mb",
            "distinct_dst_ports",
            "phishing_email_hits"
        ]
        self.is_fitted = False

    def extract_features(
        self,
        email_logs: List[Dict[str, Any]],
        auth_logs: List[Dict[str, Any]],
        network_logs: List[Dict[str, Any]]
    ) -> pd.DataFrame:
        """
        Aggregates raw events into entity-level numerical vectors per user/device.
        """
        # Discover all unique entities
        entities = set()
        for e in auth_logs:
            if e.get("user_id"):
                entities.add(e["user_id"])
        for e in email_logs:
            if e.get("user_id"):
                entities.add(e["user_id"])
        for e in network_logs:
            if e.get("user_id"):
                entities.add(e["user_id"])

        records = []
        for entity in sorted(entities):
            # Auth features
            user_auth = [e for e in auth_logs if e.get("user_id") == entity]
            failed_logins = sum(1 for e in user_auth if e.get("auth_status") == "FAILURE")
            total_auth = len(user_auth)
            distinct_ips = len(set(e.get("source_ip") for e in user_auth if e.get("source_ip")))

            # Network features (match by user or mapped device)
            user_devices = set(e.get("device_id") for e in user_auth if e.get("device_id"))
            user_net = [
                e for e in network_logs
                if e.get("user_id") == entity or (e.get("device_id") and e.get("device_id") in user_devices)
            ]
            total_bytes = sum(e.get("bytes_sent", 0) for e in user_net)
            outbound_mb = round(total_bytes / (1024 * 1024), 2)
            distinct_ports = len(set(e.get("dst_port") for e in user_net if e.get("dst_port")))

            # Email features
            user_emails = [e for e in email_logs if e.get("user_id") == entity]
            phishing_hits = sum(1 for e in user_emails if e.get("spf_status") in ["FAIL", "SOFTFAIL"] or "xyz" in (e.get("sender") or ""))

            records.append({
                "entity": entity,
                "failed_login_count": failed_logins,
                "total_auth_count": total_auth,
                "distinct_source_ips": distinct_ips,
                "outbound_bytes_mb": outbound_mb,
                "distinct_dst_ports": distinct_ports,
                "phishing_email_hits": phishing_hits
            })

        if not records:
            # Fallback mock row
            records.append({
                "entity": "placeholder",
                "failed_login_count": 0,
                "total_auth_count": 0,
                "distinct_source_ips": 0,
                "outbound_bytes_mb": 0.0,
                "distinct_dst_ports": 0,
                "phishing_email_hits": 0
            })

        return pd.DataFrame(records)

    def fit_and_predict(self, df_features: pd.DataFrame) -> pd.DataFrame:
        """
        Fits Isolation Forest on entity features and flags outliers.
        """
        df = df_features.copy()
        X = df[self.feature_names].values

        # If very few records, handle gracefully
        if len(df) < 3:
            df["is_anomaly"] = False
            df["anomaly_score"] = 0.5
            df["ml_verdict"] = "INSUFFICIENT_SAMPLE_SIZE"
            return df

        self.model.fit(X)
        self.is_fitted = True

        raw_preds = self.model.predict(X) # -1 for anomaly, 1 for inlier
        scores = self.model.decision_function(X) # lower score = more anomalous

        # Normalize score to 0.0 - 1.0 (1.0 = highest anomaly)
        min_s = scores.min()
        max_s = scores.max()
        denom = (max_s - min_s) if (max_s - min_s) != 0 else 1.0
        normalized_anomaly = 1.0 - ((scores - min_s) / denom)

        df["is_anomaly"] = raw_preds == -1
        df["anomaly_score"] = np.round(normalized_anomaly, 3)
        df["ml_verdict"] = np.where(df["is_anomaly"], "EXPERIMENTAL_ANOMALY", "NORMAL_BASELINE")

        return df
