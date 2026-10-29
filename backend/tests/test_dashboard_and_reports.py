"""
Test Suite: Cases, Vehicle Telemetry, Explainable Anomalies & Forensic Reports
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_api_health_check(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["storage_accessible"] is True
    assert data["db_accessible"] is True
    assert "features" in data
    assert data["features"]["pytorch_ml_pipeline"] is True
    assert data["features"]["mysql_database"] == "autorecon"

def test_get_cases_and_vehicle_info(client):
    resp = client.get("/api/cases")
    assert resp.status_code == 200
    cases = resp.json()
    assert len(cases) >= 1
    c0 = cases[0]
    assert "vehicle_info" in c0
    assert "vin" in c0["vehicle_info"]
    assert "location" in c0

def test_case_detail_by_id(client):
    resp = client.get("/api/cases/CASE_AF_8902")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "CASE_AF_8902"
    assert data["vehicle_info"]["make"] == "Apex EV"

def test_case_timeline_events(client):
    resp = client.get("/api/cases/CASE_AF_8902/timeline")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 3
    # Check that timestamps are ordered
    offsets = [e["time_offset_s"] for e in events]
    assert offsets == sorted(offsets)

def test_explainable_anomalies(client):
    resp = client.get("/api/cases/CASE_AF_8902/anomalies")
    assert resp.status_code == 200
    anomalies = resp.json()
    assert len(anomalies) >= 1
    a0 = anomalies[0]
    assert "parameter" in a0
    assert "observed_value" in a0
    assert "baseline_threshold" in a0
    assert "explanation" in a0
    assert "confidence" in a0
    assert "limitations" in a0

def test_evidence_correlations(client):
    resp = client.get("/api/cases/CASE_AF_8902/correlations")
    assert resp.status_code == 200
    corrs = resp.json()
    assert len(corrs) >= 1
    c0 = corrs[0]
    assert "primary_source" in c0
    assert "secondary_source" in c0
    assert "finding" in c0

def test_forensic_report_generation(client):
    resp = client.get("/api/cases/CASE_AF_8902/report?investigator_id=Lead_Det_Smith")
    assert resp.status_code == 200
    report = resp.json()
    assert "report_number" in report
    assert "regulatory_reference" in report
    assert "49 CFR Part 563" in report["regulatory_reference"]
    assert "evidence_inventory" in report
    assert "chain_of_custody_summary" in report
    assert "ml_reconstruction_analysis" in report
    assert "what_if_kinematics" in report
    assert len(report["investigative_conclusions"]) >= 2

def test_regulatory_49cfr563_endpoint(client):
    resp = client.get("/api/regulatory/49cfr563")
    assert resp.status_code == 200
    data = resp.json()
    assert "mandatory_elements_table_1" in data
    assert "compliance_notes" in data
