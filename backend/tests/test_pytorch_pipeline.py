"""
Test Suite: PyTorch & Scikit-learn Crash Severity Pipeline & API Verification
Covers:
  - FARS 2024 dataset processing and integrity
  - ColumnTransformer preprocessing and out-of-vocabulary handling
  - PyTorch neural network forward pass, softmax probabilities, and loss
  - Model loading and metadata validation (confusion matrix, metrics, year)
  - End-to-end inference with varied parameters (speed, delta-v, vehicle classes)
  - Defensive handling of invalid/unseen categorical inputs
  - FastAPI /api/ml/predict-severity and /api/ml/models integration
"""

import os
import json
import pytest
import torch
import numpy as np
import pandas as pd
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend import config
from backend.ml.dataset import (
    generate_fars_nhtsa_calibrated_dataset,
    get_or_create_fars_dataset,
    SEVERITY_CLASSES
)
from backend.ml.model import CrashSeverityNet
from backend.ml.inference import predict_crash_severity, get_ml_artifacts

@pytest.fixture(scope="module")
def client():
    from backend.database import set_engine, create_db_engine
    real_engine = create_db_engine(config.DATABASE_URL)
    set_engine(real_engine)
    return TestClient(app)

def test_fars_nhtsa_calibrated_dataset_generation():
    df = generate_fars_nhtsa_calibrated_dataset(num_samples=200, random_seed=123)
    assert len(df) == 200
    assert "pre_impact_speed_kph" in df.columns
    assert "delta_v_kph" in df.columns
    assert "seatbelt_latched" in df.columns
    assert "injury_severity" in df.columns
    assert df["injury_severity"].min() >= 0
    assert df["injury_severity"].max() <= 3

def test_fars_2024_national_dataset_cache():
    csv_path = config.ML_MODELS_DIR / "fars_2024_national_dataset.csv"
    assert csv_path.exists(), f"FARS 2024 dataset cache not found at {csv_path}"
    df = pd.read_csv(csv_path)
    assert len(df) > 50000, f"Expected >50,000 real FARS rows, got {len(df)}"
    assert set(df["injury_severity"].unique()) == {0, 1, 2, 3}
    expected_cols = [
        "pre_impact_speed_kph", "delta_v_kph", "brake_applied",
        "seatbelt_latched", "airbag_deployed", "collision_type",
        "road_condition", "vehicle_weight_class", "injury_severity"
    ]
    for col in expected_cols:
        assert col in df.columns, f"Missing required column {col}"

def test_pytorch_model_architecture_and_forward():
    model = CrashSeverityNet(input_dim=20, num_classes=4)
    model.eval()

    sample_input = torch.randn(5, 20)
    logits = model(sample_input)
    assert logits.shape == (5, 4)

    probs = model.predict_probabilities(sample_input)
    assert probs.shape == (5, 4)
    assert torch.allclose(probs.sum(dim=-1), torch.ones(5), atol=1e-4)

def test_preprocessor_transformation_and_safety():
    artifacts = get_ml_artifacts(reload=True)
    preprocessor = artifacts["preprocessor"]

    sample_df = pd.DataFrame([{
        "pre_impact_speed_kph": 65.0,
        "delta_v_kph": 25.0,
        "brake_applied": 1,
        "seatbelt_latched": 1,
        "airbag_deployed": 1,
        "collision_type": "ANGLE",
        "road_condition": "DRY",
        "vehicle_weight_class": "SEDAN"
    }])
    transformed = preprocessor.transform(sample_df)
    assert transformed.shape == (1, 20)
    assert not np.isnan(transformed).any()

    # Test unknown category (handle_unknown='ignore')
    unknown_df = pd.DataFrame([{
        "pre_impact_speed_kph": 80.0,
        "delta_v_kph": 35.0,
        "brake_applied": 0,
        "seatbelt_latched": 0,
        "airbag_deployed": 0,
        "collision_type": "UNKNOWN_GEOMETRY",
        "road_condition": "FLOODED_OIL",
        "vehicle_weight_class": "EXPERIMENTAL_HYPERCAR"
    }])
    transformed_unknown = preprocessor.transform(unknown_df)
    assert transformed_unknown.shape == (1, 20)
    assert not np.isnan(transformed_unknown).any()

def test_model_metadata_and_evaluation_metrics():
    meta_path = config.ML_MODELS_DIR / "model_metadata.json"
    assert meta_path.exists()
    with open(meta_path, "r") as f:
        meta = json.load(f)

    assert meta["dataset_year"] == 2024
    assert meta["sample_count"] > 50000
    assert "pytorch_evaluation" in meta
    assert "baseline_evaluation" in meta

    pt_eval = meta["pytorch_evaluation"]
    assert 0.40 <= pt_eval["accuracy"] <= 1.0
    assert 0.30 <= pt_eval["macro_f1"] <= 1.0
    assert len(pt_eval["confusion_matrix"]) == 4

    rf_eval = meta["baseline_evaluation"]
    assert 0.40 <= rf_eval["accuracy"] <= 1.0
    assert len(rf_eval["confusion_matrix"]) == 4

def test_pytorch_inference_endpoint():
    res = predict_crash_severity(
        pre_impact_speed_kph=65.0,
        delta_v_kph=-28.5,
        brake_applied=True,
        seatbelt_latched=True,
        airbag_deployed=True,
        collision_type="ANGLE",
        road_condition="DRY",
        vehicle_weight_class="SEDAN"
    )

    assert "predicted_severity_class" in res
    assert res["predicted_severity_class"] in SEVERITY_CLASSES
    assert 0.0 <= res["confidence"] <= 1.0
    assert "feature_contributions" in res
    assert len(res["feature_contributions"]) >= 3
    assert "disclaimer" in res
    assert "conclusive proof" in res["disclaimer"]
    assert "baseline_sklearn_comparison" in res
    assert "pytorch_evaluation" in res

def test_inference_invalid_and_edge_inputs():
    # Extreme speed and negative delta-v
    res = predict_crash_severity(
        pre_impact_speed_kph=220.0,
        delta_v_kph=-95.0,
        brake_applied=False,
        seatbelt_latched=False,
        airbag_deployed=False,
        collision_type="INVALID_TYPE",
        road_condition="UNKNOWN_CONDITION",
        vehicle_weight_class="UNKNOWN_CLASS"
    )
    assert res["predicted_severity_class"] in SEVERITY_CLASSES
    assert res["severity_risk_score"] > 50.0

def test_fastapi_ml_predict_api(client):
    payload = {
        "pre_impact_speed_kph": 72.5,
        "delta_v_kph": 31.0,
        "brake_applied": True,
        "seatbelt_latched": True,
        "airbag_deployed": True,
        "collision_type": "FRONTAL",
        "road_condition": "WET",
        "vehicle_weight_class": "SUV"
    }
    resp = client.post("/api/ml/predict-severity", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["predicted_severity_class"] in SEVERITY_CLASSES
    assert "pytorch_evaluation" in data
    assert "baseline_sklearn_comparison" in data
    assert len(data["feature_contributions"]) == 4

def test_fastapi_ml_predict_validation_errors(client):
    # Invalid speed (negative)
    resp = client.post("/api/ml/predict-severity", json={"pre_impact_speed_kph": -10.0, "delta_v_kph": 15.0})
    assert resp.status_code == 422

    # Speed exceeding bound (>250)
    resp = client.post("/api/ml/predict-severity", json={"pre_impact_speed_kph": 350.0, "delta_v_kph": 15.0})
    assert resp.status_code == 422

def test_fastapi_ml_models_registry(client):
    resp = client.get("/api/ml/models")
    assert resp.status_code == 200
    models = resp.json()
    assert len(models) >= 2
    model_ids = [m["id"] for m in models]
    assert "ML_PYTORCH_SEVERITY_V1" in model_ids
    assert "ML_SKLEARN_BASELINE_V1" in model_ids
    for m in models:
        assert m["accuracy"] > 0.40
        assert "FARS" in m["dataset_name"]
