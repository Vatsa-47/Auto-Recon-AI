"""
Test Suite: Lightweight Render Free Deployment & Optional ML Dependency Handling
Covers:
  - Graceful API startup without PyTorch / CUDA installed
  - 503 Service Unavailable responses for ML endpoints when frameworks are absent
  - Honest error reporting (no silent fake predictions)
  - Full operation of non-ML forensic, evidence, regulatory, and health endpoints
  - Preservation of full ML functionality when running in complete local dev environment
"""

import sys
import subprocess
import pytest
from unittest.mock import patch
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml import inference, pattern_model, similarity_engine
from backend import dataset_service

client = TestClient(app)


def test_health_check_in_lightweight_mode():
    """Verify that health check reports operational status and reflects ML availability."""
    with patch("backend.ml.inference.is_ml_severity_available", return_value=False):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert data["features"]["pytorch_ml_pipeline"] is False
        assert data["features"]["cfr_49_part_563_edr"] is True
        assert data["features"]["cryptographic_ledger_sha256"] is True


def test_predict_severity_unavailable_returns_503():
    """
    Verify that if PyTorch is not available, /api/ml/predict-severity returns 503 Service Unavailable
    and does not return fake or fabricated predictions.
    """
    payload = {
        "pre_impact_speed_kph": 75.0,
        "delta_v_kph": 28.5,
        "brake_applied": True,
        "seatbelt_latched": True,
        "airbag_deployed": True,
        "collision_type": "FRONTAL",
        "road_condition": "DRY",
        "vehicle_weight_class": "SEDAN"
    }

    with patch("backend.ml.inference.is_ml_severity_available", return_value=False):
        response = client.post("/api/ml/predict-severity", json=payload)
        assert response.status_code == 503
        data = response.json()
        assert "unavailable" in data["detail"].lower()
        assert "pytorch" in data["detail"].lower()


def test_predict_pattern_unavailable_returns_503():
    """
    Verify that if Scikit-learn is not available, /api/ml/predict-pattern returns 503 Service Unavailable.
    """
    payload = {
        "pre_impact_speed_kph": 60.0,
        "delta_v_kph": 20.0,
        "brake_applied": True,
        "seatbelt_latched": True,
        "airbag_deployed": True,
        "road_condition": "DRY",
        "vehicle_weight_class": "SEDAN"
    }

    with patch("backend.ml.pattern_model.is_pattern_model_available", return_value=False):
        response = client.post("/api/ml/predict-pattern", json=payload)
        assert response.status_code == 503
        data = response.json()
        assert "unavailable" in data["detail"].lower()
        assert "pattern" in data["detail"].lower()


def test_similar_crashes_unavailable_returns_503():
    """
    Verify that if Similarity Engine is not available, /api/ml/similar-crashes returns 503.
    """
    payload = {
        "pre_impact_speed_kph": 80.0,
        "delta_v_kph": 30.0,
        "collision_type": "ANGLE",
        "road_condition": "WET",
        "vehicle_weight_class": "SUV",
        "seatbelt_latched": True,
        "airbag_deployed": True,
        "top_k": 3
    }

    with patch("backend.ml.similarity_engine.is_similarity_engine_available", return_value=False):
        response = client.post("/api/ml/similar-crashes", json=payload)
        assert response.status_code == 503
        data = response.json()
        assert "unavailable" in data["detail"].lower()


def test_non_ml_endpoints_operate_without_pytorch():
    """
    Verify that non-ML forensic, regulatory, evidence, and FARS endpoints
    operate without requiring PyTorch or ML frameworks.
    """
    # 1. Regulatory 49 CFR Part 563 reference
    reg_res = client.get("/api/regulatory/49cfr563")
    assert reg_res.status_code == 200
    assert "49 CFR Part 563" in reg_res.json()["regulation"]

    # 2. Evidence listing
    ev_res = client.get("/api/evidence")
    assert ev_res.status_code == 200
    assert isinstance(ev_res.json(), list)

    # 3. FARS Historical scenarios listing
    fars_res = client.get("/api/reconstruction/fars-cases")
    assert fars_res.status_code == 200
    assert isinstance(fars_res.json(), list)


def test_local_dev_full_ml_functionality_preserved():
    """
    Verify that when running in full local development environment with PyTorch and Scikit-learn,
    ML severity inference executes and returns valid neural network predictions.
    """
    if not inference.is_ml_severity_available():
        pytest.skip("PyTorch not installed in this environment; skipping local dev execution test.")

    payload = {
        "pre_impact_speed_kph": 70.0,
        "delta_v_kph": 32.0,
        "brake_applied": True,
        "seatbelt_latched": True,
        "airbag_deployed": True,
        "collision_type": "FRONTAL",
        "road_condition": "DRY",
        "vehicle_weight_class": "SEDAN"
    }

    response = client.post("/api/ml/predict-severity", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "predicted_severity_class" in data
    assert "severity_risk_score" in data
    assert "pytorch_evaluation" in data
    assert "baseline_sklearn_comparison" in data
    assert "feature_contributions" in data


def test_dataset_service_import_without_pandas():
    """
    Verify backend.dataset_service imports successfully without Pandas installed,
    leveraging 'from __future__ import annotations' so type annotations like
    df: pd.DataFrame do not cause NameError or AttributeError.
    """
    code = (
        "import sys\n"
        "sys.modules['pandas'] = None\n"
        "from backend import dataset_service\n"
        "assert dataset_service.PANDAS_AVAILABLE is False\n"
        "assert dataset_service.pd is None\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"Import without pandas failed: {result.stderr}"


def test_pandas_dependent_service_operations_fail_gracefully_when_pandas_missing():
    """
    Verify that functions in backend.dataset_service that require pandas explicitly
    check PANDAS_AVAILABLE and raise clear, controlled errors (HTTP 503 or RuntimeError)
    rather than failing with unhandled exceptions.
    """
    with patch.object(dataset_service, "PANDAS_AVAILABLE", False), patch.object(dataset_service, "pd", None):
        # 1. parse_dataset_bytes raises HTTP 503
        with pytest.raises(HTTPException) as exc_info:
            dataset_service.parse_dataset_bytes(b"col1,col2\n1,2", "test.csv")
        assert exc_info.value.status_code == 503
        assert "pandas is not installed" in exc_info.value.detail

        # 2. save_and_ingest_dataset raises HTTP 503
        with pytest.raises(HTTPException) as exc_info:
            dataset_service.save_and_ingest_dataset(b"col1,col2\n1,2", "test.csv")
        assert exc_info.value.status_code == 503
        assert "pandas is not installed" in exc_info.value.detail

        # 3. analyze_and_reconstruct_dataset raises HTTP 503
        with pytest.raises(HTTPException) as exc_info:
            dataset_service.analyze_and_reconstruct_dataset("ds-nonexistent", None)
        assert exc_info.value.status_code == 503
        assert "pandas is not installed" in exc_info.value.detail

        # 4. detect_dataset_type_and_schema raises RuntimeError
        with pytest.raises(RuntimeError) as exc_info:
            dataset_service.detect_dataset_type_and_schema(None)
        assert "requires 'pandas'" in str(exc_info.value)

        # 5. generate_schema_summary raises RuntimeError
        with pytest.raises(RuntimeError) as exc_info:
            dataset_service.generate_schema_summary(None, {}, "GENERAL", [])
        assert "requires 'pandas'" in str(exc_info.value)


def test_dataset_upload_endpoint_returns_503_when_pandas_missing():
    """
    Verify that /api/datasets/upload returns HTTP 503 with a clear message
    when pandas is not installed.
    """
    with patch.object(dataset_service, "PANDAS_AVAILABLE", False), patch.object(dataset_service, "pd", None):
        files = {"file": ("test.csv", b"time,speed\n0.0,50.0", "text/csv")}
        response = client.post("/api/datasets/upload", files=files)
        assert response.status_code == 503
        data = response.json()
        assert "pandas is not installed" in data["detail"].lower()
