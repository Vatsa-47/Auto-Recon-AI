"""
AUTO-RECON AI — Dataset Ingestion, ML Inference, Kinematic Reconstruction,
Multi-Channel Graphs, and PDF Report Test Suite.
"""

import io
import json
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

SAMPLE_CSV = """timestamp_ms,speed_kph,long_accel_g,lat_accel_g,yaw_rate_dps,steering_deg,brake_applied,throttle_pct
0,72.4,-0.02,0.01,0.2,0.5,0,24.0
500,72.1,-0.05,0.01,0.1,0.2,0,24.0
1000,71.8,-0.08,0.02,0.0,0.0,0,23.5
1500,71.5,-0.10,0.01,-0.1,-0.2,0,23.0
2000,69.2,-0.45,-0.05,-0.5,-1.2,1,0.0
2500,58.0,-0.82,-0.12,-1.2,-3.5,1,0.0
3000,42.5,-1.15,-0.25,-2.5,-6.0,1,0.0
3100,0.0,-4.50,-0.80,-5.0,-8.0,1,0.0
""".encode("utf-8")

SAMPLE_JSON = json.dumps([
    {"time_ms": 0, "speed_kph": 65.0, "brake": 0, "accel_g": -0.05},
    {"time_ms": 1000, "speed_kph": 64.5, "brake": 0, "accel_g": -0.05},
    {"time_ms": 2000, "speed_kph": 50.0, "brake": 1, "accel_g": -0.65},
    {"time_ms": 3000, "speed_kph": 0.0, "brake": 1, "accel_g": -3.80}
]).encode("utf-8")

def test_preview_csv_endpoint():
    response = client.post(
        "/api/datasets/preview",
        files={"file": ("test_run.csv", io.BytesIO(SAMPLE_CSV), "text/csv")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["file_format"] == "CSV"
    assert data["dataset_type"] == "TELEMETRY_TIMESERIES"
    assert data["total_rows"] == 8
    assert data["total_columns"] == 8
    schema_sum = data["schema_summary"]
    assert "speed_kph" in schema_sum["available_reconstruction_fields"]
    assert "brake" in schema_sum["available_reconstruction_fields"]

def test_preview_json_endpoint():
    response = client.post(
        "/api/datasets/preview",
        files={"file": ("telemetry.json", io.BytesIO(SAMPLE_JSON), "application/json")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["file_format"] == "JSON"
    assert data["total_rows"] == 4
    assert data["total_columns"] == 4

def test_reject_unsupported_file_extension():
    response = client.post(
        "/api/datasets/preview",
        files={"file": ("executable.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Unsupported dataset format" in response.json()["detail"]

def test_reject_oversized_file():
    huge_data = b"0" * (51 * 1024 * 1024)
    response = client.post(
        "/api/datasets/preview",
        files={"file": ("huge.csv", io.BytesIO(huge_data), "text/csv")}
    )
    assert response.status_code in [400, 413]

def test_dataset_upload_persistence():
    response = client.post(
        "/api/datasets/upload",
        files={"file": ("field_trial_01.csv", io.BytesIO(SAMPLE_CSV), "text/csv")},
        data={"case_id": "CASE_AF_8902"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["dataset_id"].startswith("DS-")
    assert len(data["sha256"]) == 64
    assert data["total_rows"] == 8
    assert data["dataset_type"] == "TELEMETRY_TIMESERIES"

    ds_id = data["dataset_id"]

    # Verify listing
    list_resp = client.get("/api/datasets")
    assert list_resp.status_code == 200
    datasets = list_resp.json()
    assert any(d["id"] == ds_id for d in datasets)

    # Verify single fetch
    get_resp = client.get(f"/api/datasets/{ds_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == ds_id

def test_dataset_ml_analysis_and_reconstruction():
    # 1. Upload dataset
    upload_resp = client.post(
        "/api/datasets/upload",
        files={"file": ("impact_trial_02.csv", io.BytesIO(SAMPLE_CSV), "text/csv")},
        data={"case_id": "CASE_AF_8902"}
    )
    assert upload_resp.status_code == 201
    ds_id = upload_resp.json()["dataset_id"]

    # 2. Trigger analysis
    anl_resp = client.post(f"/api/datasets/{ds_id}/analyze")
    assert anl_resp.status_code == 200
    anl_data = anl_resp.json()
    assert anl_data["dataset_id"] == ds_id
    assert "predicted_severity_class" in anl_data["ml_predictions"]["severity"]
    assert "predicted_pattern" in anl_data["ml_predictions"]["collision_pattern"]
    assert len(anl_data["ml_predictions"]["similar_crashes"]) > 0

    # 3. Retrieve kinematic scenario
    scen_resp = client.get(f"/api/datasets/{ds_id}/scenario")
    assert scen_resp.status_code == 200
    scen_data = scen_resp.json()
    assert "telemetry" in scen_data
    assert len(scen_data["telemetry"]) > 0
    assert "speed" in scen_data["telemetry"][0]

    # 4. Retrieve multi-channel dynamic graphs
    graph_resp = client.get(f"/api/datasets/{ds_id}/graphs")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "speed_vs_time" in graph_data
    assert "accel_vs_time" in graph_data
    assert "delta_v_vs_time" in graph_data

    # 5. Generate and download court-ready PDF forensic report
    gen_resp = client.post(
        "/api/reports/generate",
        json={
            "dataset_id": ds_id,
            "lead_investigator": "Forensic Engineer #1024",
            "title": "Comprehensive Test Incident Report"
        }
    )
    assert gen_resp.status_code == 200
    rep_data = gen_resp.json()
    rep_id = rep_data["report_id"]

    # Verify JSON export
    rep_json_resp = client.get(f"/api/reports/{rep_id}")
    assert rep_json_resp.status_code == 200
    assert rep_json_resp.json()["report_id"] == rep_id

    # Verify PDF download & binary magic header
    pdf_resp = client.get(f"/api/reports/{rep_id}/download")
    assert pdf_resp.status_code == 200
    assert pdf_resp.content.startswith(b"%PDF")
    assert len(pdf_resp.content) > 1000

def test_evidence_auto_ingestion_integration():
    # Verify that uploading a CSV through the existing /api/evidence endpoint auto-creates a Dataset
    response = client.post(
        "/api/evidence",
        files={"file": ("field_can_log.csv", io.BytesIO(SAMPLE_CSV), "text/csv")},
        data={
            "case_id": "CASE_AF_8902",
            "evidence_type": "TELEMETRY_LOG",
            "investigator_id": "Forensic_Lead_01"
        }
    )
    assert response.status_code == 201
    ev_data = response.json()
    assert "sha256" in ev_data
    assert ev_data["status"] in ["VERIFIED", "UNVERIFIED"]

    # Check that it appeared in datasets
    list_resp = client.get("/api/datasets")
    assert list_resp.status_code == 200
    datasets = list_resp.json()
    assert any("field_can_log.csv" in d["filename"] for d in datasets)

def test_statistical_distributions_endpoint():
    response = client.get("/api/graphs/distributions")
    assert response.status_code == 200
    dist_data = response.json()
    assert "crash_severity_distribution" in dist_data
    assert "collision_pattern_distribution" in dist_data
    assert "environmental_conditions" in dist_data
