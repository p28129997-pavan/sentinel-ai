import pytest
from pipeline import run_detection_pipeline

def test_pipeline_benchmarks():
    result = run_detection_pipeline()
    metrics = result["metrics"]

    assert metrics["campaigns_expected"] == 3
    assert metrics["campaigns_detected"] == 3
    assert metrics["campaigns_missed"] == 0
    assert metrics["precision"] >= 0.80
    assert metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert "Benchmark calculated against synthetic validation scenario data" in metrics["disclaimer"]
