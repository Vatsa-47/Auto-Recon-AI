import pytest
import hashlib
from pathlib import Path
from sqlalchemy import text
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import get_engine, get_session_factory, UploadedDatasetModel, init_db
from backend.dataset_service import save_and_ingest_dataset, analyze_and_reconstruct_dataset

SAMPLE_CSV = """case_id,vehicle_id,time_s,speed_kph,longitudinal_accel_mps2,lateral_accel_mps2,steering_angle_deg,brake_applied,throttle_pct,heading_deg,position_x_m,position_y_m,delta_v_kph,event_label,collision_type,road_condition,vehicle_weight_class,airbag_deployed,seatbelt_latched,data_origin
SYNTH-ANGLE-001,VEHICLE-A,0.0,72,-0.2,0.1,0,false,18,0,0,0,0,normal_driving,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,0.2,72,-0.3,0.1,0,false,18,0,4,0,0,normal_driving,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,0.4,71,-0.5,0.2,1,false,17,1,7.9,0.1,0,normal_driving,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,0.6,71,-0.8,0.3,2,true,10,2,11.8,0.1,0,braking_started,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,0.8,69,-2.5,0.8,5,true,0,5,15.6,0.2,0,hard_braking,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,1.0,65,-4.8,1.4,9,true,0,10,19.2,0.5,0,steering_evasion,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,1.2,59,-6.2,2.1,14,true,0,18,22.4,1.0,0,steering_evasion,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,1.4,52,-7.0,2.8,18,true,0,28,25.1,1.5,0,impact_approach,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,1.6,44,-8.5,3.1,22,true,0,35,27.0,2.0,0,impact_approach,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,1.8,36,-10.0,2.5,24,true,0,42,28.1,2.5,0,impact_approach,ANGLE,DRY,SEDAN,false,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,2.0,30,-12.0,1.2,18,true,0,35,29.0,3.0,3,estimated_impact,ANGLE,DRY,SEDAN,true,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,2.2,18,-15.0,0.5,8,true,0,25,29.4,20,20,post_impact_deceleration,ANGLE,DRY,SEDAN,true,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,2.4,8,-12.0,0.2,3,true,0,20,29.5,38,38,post_impact_deceleration,ANGLE,DRY,SEDAN,true,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,2.6,2,-5.0,0.0,0,true,0,18,29.5,40,40,vehicle_stopped,ANGLE,DRY,SEDAN,true,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,2.8,0,-0.5,0.0,0,true,0,18,29.5,40,40,vehicle_stopped,ANGLE,DRY,SEDAN,true,true,SYNTHETIC
SYNTH-ANGLE-001,VEHICLE-A,3.0,0,0.0,0.0,0,true,0,18,29.5,40,40,vehicle_stopped,ANGLE,DRY,SEDAN,true,true,SYNTHETIC
"""

def test_uploaded_datasets_persistence_and_sql_query():
    client = TestClient(app)
    csv_bytes = SAMPLE_CSV.encode("utf-8")
    expected_hash = hashlib.sha256(csv_bytes).hexdigest()
    expected_size = len(csv_bytes)

    # 1. Test POST /api/evidence upload
    response = client.post(
        "/api/evidence",
        data={
            "case_id": "CASE_AF_8902",
            "evidence_type": "TELEMETRY_DATA",
            "investigator_id": "Lead_Investigator"
        },
        files={
            "file": ("auto_recon_synthetic_angle_crash.csv", csv_bytes, "text/csv")
        }
    )
    assert response.status_code == 201
    ev_data = response.json()
    assert ev_data["filename"] == "auto_recon_synthetic_angle_crash.csv"
    assert ev_data["sha256"] == expected_hash

    # 2. Check persistence in uploaded_datasets table
    db = get_session_factory()()
    try:
        up_rec = db.query(UploadedDatasetModel).filter(
            UploadedDatasetModel.original_filename == "auto_recon_synthetic_angle_crash.csv"
        ).order_by(UploadedDatasetModel.upload_timestamp.desc()).first()
        assert up_rec is not None
        assert up_rec.file_size_bytes == expected_size
        assert up_rec.sha256_hash == expected_hash
        assert hashlib.sha256(up_rec.file_data).hexdigest() == expected_hash
        assert len(up_rec.file_data) == expected_size

        # Check analysis & reconstruction
        analysis = analyze_and_reconstruct_dataset(dataset_id=up_rec.id, db=db)
        assert analysis["status"] == "COMPLETED"
        assert analysis["scenario_id"] is not None
        assert up_rec.scenario_id == analysis["scenario_id"]
        assert up_rec.processing_status == "ANALYZED"

        # Verify unit conversions & telemetry extraction
        scen = analysis["reconstruction_scenario"]
        telemetry = scen["telemetry"]
        assert len(telemetry) == 16
        # At t=2.2s: longitudinal_accel_mps2 = -15.0 -> longG = -15.0 / 9.80665 ~ -1.53 g
        t_22 = [p for p in telemetry if abs(p["t"] - 2.2) < 0.05][0]
        assert abs(t_22["longG"] - (-15.0 / 9.80665)) < 0.02
        assert t_22["posX"] == 29.4
        assert t_22["posY"] == 20.0
        assert t_22["deltaV"] == 20.0

        # Verify single vehicle rule (no second vehicle fabricated)
        assert scen["vehicles"]["target"] is None
        assert "Subject Vehicle (VEHICLE-A)" in scen["vehicles"]["ego"]["label"]

        # Verify synthetic disclaimer
        assert "Single-vehicle synthetic" in scen["provenance"]["synthetic_disclaimer"]
    finally:
        db.close()

    # 3. Verify SQL query matches requirements
    engine = get_engine()
    if engine.dialect.name == "mysql":
        with engine.connect() as conn:
            sql = text("""
                SELECT id, original_filename, file_format, file_size_bytes, 
                       SHA2(file_data, 256) AS stored_file_sha256, sha256_hash, 
                       processing_status, scenario_id, upload_timestamp,
                       OCTET_LENGTH(file_data) AS blob_len
                FROM uploaded_datasets
                WHERE original_filename = 'auto_recon_synthetic_angle_crash.csv'
                ORDER BY upload_timestamp DESC
                LIMIT 1;
            """)
            row = conn.execute(sql).fetchone()
            assert row is not None
            assert row[4].lower() == row[5].lower()  # stored_file_sha256 == sha256_hash
            assert row[3] == row[9]  # file_size_bytes == blob_len

    # 4. Verify refresh persistence: GET /api/cases/CASE_AF_8902/evidence MUST return the CSV
    resp_cases = client.get("/api/cases/CASE_AF_8902/evidence")
    assert resp_cases.status_code == 200
    items = resp_cases.json()
    assert any(i["filename"] == "auto_recon_synthetic_angle_crash.csv" for i in items)

    # 5. Verify GET /api/datasets/{dataset_id}/export-scenario
    resp_export = client.get(f"/api/datasets/{up_rec.id}/export-scenario")
    assert resp_export.status_code == 200
    exp_json = resp_export.json()
    assert "telemetry" in exp_json
    assert "vehicles" in exp_json
    assert len(exp_json["telemetry"]) == 16
