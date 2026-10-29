import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline import run_detection_pipeline

OUTPUT_PATH = ROOT / "public" / "data" / "dashboard.json"


def compact_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        key: event.get(key)
        for key in (
            "event_id",
            "source",
            "timestamp",
            "user_id",
            "device_id",
            "ip_address",
            "scenario_tag",
            "summary",
        )
    }


def compact_incident(incident: dict[str, Any]) -> dict[str, Any]:
    return {
        key: incident.get(key)
        for key in (
            "incident_id",
            "title",
            "campaign_tag",
            "status",
            "severity",
            "risk_score",
            "confidence",
            "detected_at",
            "primary_user",
            "primary_device",
            "primary_ip",
            "rule_ids",
            "timeline",
            "explanation",
            "recommended_actions",
        )
    } | {
        "correlated_events": [
            {
                key: event.get(key)
                for key in (
                    "event_id",
                    "source",
                    "stage",
                    "correlation_reason",
                )
            }
            for event in incident.get("correlated_events", [])
        ]
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        result = run_detection_pipeline(
            db_path=str(Path(temp_dir) / "sentinel.db")
        )

    dashboard = {
        "generated_at": result["incidents"][0]["detected_at"]
        if result["incidents"]
        else None,
        "events": [compact_event(event) for event in result["events"]],
        "incidents": [
            compact_incident(incident) for incident in result["incidents"]
        ],
        "metrics": result["metrics"],
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(dashboard, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Exported {len(dashboard['incidents'])} incidents and "
          f"{len(dashboard['events'])} events to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
