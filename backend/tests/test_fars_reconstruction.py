"""
Test Suite: FARS 2024 Models, Event Sequence Analysis, Similarity Engine, and Reconstruction APIs
Covers:
  - Crash Pattern Model (Model B)
  - Event Sequence Analyzer (Model C)
  - Similarity Search Engine (Model D)
  - FARS MySQL Service & Curated Scenarios
  - FastAPI endpoints for pattern prediction, similarity matching, and scene configurations
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend import config
from backend.ml.pattern_model import predict_crash_pattern, get_pattern_artifacts
from backend.ml.event_analyzer import get_event_analyzer
from backend.ml.similarity_engine import get_similarity_engine
from backend.fars_service import get_all_fars_cases, get_fars_scenario
from backend.database import get_db

@pytest.fixture(scope="module", autouse=True)
def setup_engine():
    from backend.database import set_engine, create_db_engine
    real_engine = create_db_engine(config.DATABASE_URL)
    set_engine(real_engine)
    yield
    real_engine = create_db_engine(config.DATABASE_URL)
    set_engine(real_engine)

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

def test_pattern_model_inference():
    res = predict_crash_pattern(
        pre_impact_speed_kph=60.0,
        delta_v_kph=25.0,
        brake_applied=True,
        road_condition="DRY",
        vehicle_weight_class="SEDAN"
    )
    assert "predicted_pattern" in res
    assert res["predicted_pattern"] in ["FRONTAL", "ANGLE", "REAR", "ROLLOVER", "SIDESWIPE"]
    assert 0.0 <= res["confidence"] <= 1.0
    assert "pattern_probabilities" in res
    assert "dataset_provenance" in res

def test_pattern_artifacts_loaded():
    artifacts = get_pattern_artifacts()
    assert "model" in artifacts
    assert "preprocessor" in artifacts

def test_event_sequence_analyzer():
    analyzer = get_event_analyzer()
    events = [
        {"event_number": 1, "soe_code": 63, "soe_name": "Ran Off Roadway - Right"},
        {"event_number": 2, "soe_code": 42, "soe_name": "Tree (Standing)"},
        {"event_number": 3, "soe_code": 1, "soe_name": "Rollover/Overturn"}
    ]
    analysis = analyzer.analyze_sequence(events)
    assert analysis["sequence_length"] == 3
    assert analysis["first_harmful_event"] is not None
    assert analysis["has_rollover"] is True

def test_similarity_search_engine():
    engine = get_similarity_engine()
    matches = engine.find_similar_crashes(
        pre_impact_speed_kph=55.0,
        delta_v_kph=30.0,
        collision_type="FRONTAL",
        road_condition="DRY",
        top_k=3
    )
    assert isinstance(matches, list)
    assert len(matches) == 3
    for match in matches:
        assert "similarity_score" in match
        assert 0.0 <= match["similarity_score"] <= 100.0
        assert "collision_type" in match
        assert "comparable_factors" in match

def test_fars_service_database_retrieval():
    with next(get_db()) as db:
        cases = get_all_fars_cases(db)
        assert len(cases) >= 5
        case_ids = [c["id"] for c in cases]
        assert "FARS-2024-10007" in case_ids
        assert "FARS-2024-10009" in case_ids
        assert "FARS-2024-10015" in case_ids

        # Fetch reconstruction scenario
        scenario = get_fars_scenario("FARS-2024-10007", db)
        assert scenario is not None
        assert "forensic_provenance" in scenario
        assert "actors" in scenario
        assert "ego" in scenario["actors"]

def test_fastapi_pattern_endpoint(client):
    payload = {
        "pre_impact_speed_kph": 75.0,
        "delta_v_kph": 30.0,
        "brake_applied": True,
        "road_condition": "WET",
        "vehicle_weight_class": "SUV"
    }
    resp = client.post("/api/ml/predict-pattern", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "predicted_pattern" in data
    assert "confidence" in data
    assert "pattern_probabilities" in data

def test_fastapi_similarity_endpoint(client):
    payload = {
        "pre_impact_speed_kph": 65.0,
        "delta_v_kph": 28.0,
        "collision_type": "ANGLE",
        "road_condition": "DRY",
        "top_k": 4
    }
    resp = client.post("/api/ml/similar-crashes", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "matched_crashes" in data
    assert len(data["matched_crashes"]) == 4

def test_fastapi_reconstruction_fars_cases(client):
    resp = client.get("/api/reconstruction/fars-cases")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 5

    # Case detail
    resp_detail = client.get("/api/reconstruction/fars-cases/FARS-2024-10007")
    assert resp_detail.status_code == 200
    detail = resp_detail.json()
    assert detail["id"] == "FARS-2024-10007"

    # Scene scenario
    resp_scen = client.get("/api/reconstruction/scenario/FARS-2024-10007")
    assert resp_scen.status_code == 200
    scen = resp_scen.json()
    assert "case_id" in scen
    assert "actors" in scen
    assert "ego" in scen["actors"]
