import hashlib
import os
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.main import app
from backend.database import (
    init_db,
    set_engine,
    create_db_engine,
    EvidenceModel,
    AuditLogModel,
    get_session_factory
)
import backend.config as config
from backend.migrate_sqlite_to_mysql import run_migration

@pytest.fixture(scope="function")
def test_env():
    # Create isolated temp dirs for db and storage
    temp_dir = tempfile.mkdtemp()
    test_db = Path(temp_dir) / "test_autorecon.db"
    test_storage = Path(temp_dir) / "test_storage"
    test_storage.mkdir(parents=True, exist_ok=True)

    test_url = f"sqlite:///{test_db.as_posix()}"
    test_engine = create_db_engine(test_url)

    # Patch config paths and database engine
    orig_url = config.DATABASE_URL
    orig_storage = config.STORAGE_DIR
    orig_db_path = config.DB_PATH

    config.DATABASE_URL = test_url
    config.STORAGE_DIR = test_storage
    config.DB_PATH = test_db
    set_engine(test_engine)

    init_db(test_engine)

    with TestClient(app) as client:
        yield {
            "client": client,
            "storage": test_storage,
            "db_path": test_db,
            "engine": test_engine,
            "temp_dir": Path(temp_dir)
        }

    # Cleanup
    config.DATABASE_URL = orig_url
    config.STORAGE_DIR = orig_storage
    config.DB_PATH = orig_db_path
    set_engine(None)
    shutil.rmtree(temp_dir, ignore_errors=True)

# -------------------------------------------------------------
# 11 PRESERVED CORE EVIDENCE API TESTS
# -------------------------------------------------------------

def test_health_check(test_env):
    client = test_env["client"]
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["storage_accessible"] is True
    assert data["db_accessible"] is True
    assert "SQLite" in data["db_type"] or "MySQL" in data["db_type"]

def test_evidence_upload_unverified_by_default(test_env):
    client = test_env["client"]
    file_bytes = b"CAN_BUS_DUMP_AF01_RAW_FRAME_DATA_12345"
    expected_hash = hashlib.sha256(file_bytes).hexdigest()

    resp = client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_01", "evidence_type": "CAN_BUS_DUMP"},
        files={"file": ("can_test.log", file_bytes, "text/plain")}
    )
    assert resp.status_code == 201
    item = resp.json()
    assert item["case_id"] == "CASE_AF_01"
    assert item["filename"] == "can_test.log"
    assert item["sha256"] == expected_hash
    assert item["trusted_reference"] is None
    # CRITICAL: Must be UNVERIFIED when no trusted reference is provided
    assert item["status"] == "UNVERIFIED"

def test_evidence_upload_with_matching_reference(test_env):
    client = test_env["client"]
    file_bytes = b"EDR_CRASH_DATA_BINARY_STREAM_OCTET"
    expected_hash = hashlib.sha256(file_bytes).hexdigest()

    resp = client.post(
        "/api/evidence",
        data={
            "case_id": "CASE_AF_01",
            "evidence_type": "EDR_BINARY",
            "trusted_reference": expected_hash
        },
        files={"file": ("edr_test.bin", file_bytes, "application/octet-stream")}
    )
    assert resp.status_code == 201
    item = resp.json()
    assert item["sha256"] == expected_hash
    assert item["trusted_reference"] == expected_hash
    assert item["status"] == "VERIFIED"

def test_evidence_upload_with_mismatching_reference(test_env):
    client = test_env["client"]
    file_bytes = b"AUTHENTIC_DASHCAM_FOOTAGE_BYTES"
    fake_hash = "0" * 64

    resp = client.post(
        "/api/evidence",
        data={
            "case_id": "CASE_AF_01",
            "evidence_type": "DASHCAM_VIDEO",
            "trusted_reference": fake_hash
        },
        files={"file": ("dashcam.mp4", file_bytes, "video/mp4")}
    )
    assert resp.status_code == 201
    item = resp.json()
    assert item["status"] == "MISMATCH"

def test_set_reference_and_verify(test_env):
    client = test_env["client"]
    file_bytes = b"TELEMETRY_SAMPLE_FILE_DATA"
    real_hash = hashlib.sha256(file_bytes).hexdigest()

    # Upload unverified
    resp = client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_02"},
        files={"file": ("telemetry.csv", file_bytes, "text/csv")}
    )
    assert resp.status_code == 201
    ev_id = resp.json()["id"]
    assert resp.json()["status"] == "UNVERIFIED"

    # Set trusted reference
    resp = client.post(
        f"/api/evidence/{ev_id}/reference",
        json={"reference_hash": real_hash, "actor_id": "Forensic_Examiner"}
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["trusted_reference"] == real_hash
    assert updated["status"] == "VERIFIED"

def test_tamper_detection_on_disk(test_env):
    client = test_env["client"]
    storage = test_env["storage"]
    file_bytes = b"ORIGINAL_BRAKE_PRESSURE_RECORD"
    real_hash = hashlib.sha256(file_bytes).hexdigest()

    # Upload verified
    resp = client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_01", "trusted_reference": real_hash},
        files={"file": ("brake_sensor.dat", file_bytes, "application/octet-stream")}
    )
    assert resp.status_code == 201
    ev_id = resp.json()["id"]
    assert resp.json()["status"] == "VERIFIED"

    # Find file in storage and tamper with it!
    stored_files = list(storage.glob(f"{ev_id}_*"))
    assert len(stored_files) == 1
    with open(stored_files[0], "wb") as f:
        f.write(b"TAMPERED_INJECTED_CORRUPTED_BYTES")

    # Run verification API
    v_resp = client.post(f"/api/evidence/{ev_id}/verify", json={"actor_id": "Auditor"})
    assert v_resp.status_code == 200
    res = v_resp.json()
    assert res["status"] == "MISMATCH"
    assert res["match"] is False
    assert "VIOLATION" in res["message"]

    # Check evidence item state in DB
    item = client.get(f"/api/evidence/{ev_id}").json()
    assert item["status"] == "MISMATCH"

def test_missing_file_reports_error(test_env):
    client = test_env["client"]
    storage = test_env["storage"]
    file_bytes = b"SOME_DATA_TO_DELETE"

    resp = client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_03"},
        files={"file": ("to_delete.bin", file_bytes, "application/octet-stream")}
    )
    ev_id = resp.json()["id"]

    # Delete storage file
    stored_files = list(storage.glob(f"{ev_id}_*"))
    for f in stored_files:
        f.unlink()

    # Verify
    v_resp = client.post(f"/api/evidence/{ev_id}/verify")
    assert v_resp.status_code == 200
    res = v_resp.json()
    assert res["status"] == "ERROR"
    assert res["match"] is False

def test_audit_log_hash_chain_integrity(test_env):
    client = test_env["client"]
    file_bytes = b"CHAIN_TEST_DATA"
    real_hash = hashlib.sha256(file_bytes).hexdigest()

    # Upload
    resp = client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_04"},
        files={"file": ("chain_doc.log", file_bytes, "text/plain")}
    )
    ev_id = resp.json()["id"]

    # Add reference
    client.post(
        f"/api/evidence/{ev_id}/reference",
        json={"reference_hash": real_hash}
    )

    # Verify
    client.post(f"/api/evidence/{ev_id}/verify")

    # Fetch audit history
    h_resp = client.get(f"/api/evidence/{ev_id}/history")
    assert h_resp.status_code == 200
    history_data = h_resp.json()
    assert history_data["chain_valid"] is True
    assert history_data["total_events"] >= 3
    events = history_data["history"]
    types = [e["event_type"] for e in events]
    assert "INGESTION" in types
    assert "REFERENCE_ADDED" in types
    assert "INTEGRITY_VERIFICATION" in types

def test_invalid_hash_validation(test_env):
    client = test_env["client"]
    # Upload evidence
    resp = client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_05"},
        files={"file": ("invalid_hash_test.log", b"12345", "text/plain")}
    )
    ev_id = resp.json()["id"]

    # Send non-64 hex char hash
    bad_resp = client.post(
        f"/api/evidence/{ev_id}/reference",
        json={"reference_hash": "not_a_valid_hex_hash"}
    )
    assert bad_resp.status_code == 422

def test_case_evidence_filter_and_verify_all(test_env):
    client = test_env["client"]
    # Upload item for case AF_01
    client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_01"},
        files={"file": ("f1.dat", b"111", "application/octet-stream")}
    )
    # Upload item for case AF_02
    client.post(
        "/api/evidence",
        data={"case_id": "CASE_AF_02"},
        files={"file": ("f2.dat", b"222", "application/octet-stream")}
    )

    # Filter by case
    resp1 = client.get("/api/cases/CASE_AF_01/evidence")
    assert resp1.status_code == 200
    items1 = resp1.json()
    assert all(i["case_id"] == "CASE_AF_01" for i in items1)

    # Verify all for case
    v_resp = client.post("/api/evidence/verify-all?case_id=CASE_AF_01")
    assert v_resp.status_code == 200
    results = v_resp.json()
    assert len(results) >= 1

def test_not_found_handling(test_env):
    client = test_env["client"]
    resp = client.get("/api/evidence/ev-non-existent-999")
    assert resp.status_code == 404

    resp_hist = client.get("/api/evidence/ev-non-existent-999/history")
    assert resp_hist.status_code == 404

# -------------------------------------------------------------
# NEW MIGRATION, PERSISTENCE, ROLLBACK & RESILIENCE TESTS
# -------------------------------------------------------------

def test_persistent_evidence_and_audit_across_reconnect(test_env):
    """Test that records persist in database across session re-creation."""
    client = test_env["client"]
    file_bytes = b"PERSISTENCE_TEST_BYTES"
    h = hashlib.sha256(file_bytes).hexdigest()

    resp = client.post(
        "/api/evidence",
        data={"case_id": "CASE_PERSIST_01", "trusted_reference": h},
        files={"file": ("persist.bin", file_bytes, "application/octet-stream")}
    )
    assert resp.status_code == 201
    ev_id = resp.json()["id"]

    # Re-query using a fresh direct database session
    factory = get_session_factory()
    session = factory()
    try:
        ev = session.get(EvidenceModel, ev_id)
        assert ev is not None
        assert ev.sha256 == h
        assert ev.status == "VERIFIED"

        events = session.query(AuditLogModel).filter(AuditLogModel.evidence_id == ev_id).all()
        assert len(events) >= 2
    finally:
        session.close()

def test_transaction_rollback_on_failure(test_env):
    """Test that transactions roll back cleanly when an error occurs during ingestion."""
    factory = get_session_factory()
    session = factory()
    initial_count = session.query(EvidenceModel).count()
    session.close()

    client = test_env["client"]
    # Attempt upload with missing required form field to trigger failure
    bad_resp = client.post(
        "/api/evidence",
        data={},  # Missing case_id
        files={"file": ("fail.bin", b"some_bytes", "application/octet-stream")}
    )
    assert bad_resp.status_code == 422

    # Verify no partial rows were committed
    session = factory()
    try:
        assert session.query(EvidenceModel).count() == initial_count
    finally:
        session.close()

def test_database_configuration_url_helper_and_masking():
    """Test safe database URL generation and password masking."""
    url = config.build_database_url(
        user="test_user",
        password="super_secret_password",
        host="10.0.0.1",
        port=3306,
        name="test_db"
    )
    assert "super_secret_password" in url
    assert "mysql+pymysql://" in url

    safe_url = config.get_database_url_safe(url)
    assert "super_secret_password" not in safe_url
    assert "****" in safe_url
    assert "test_user" in safe_url

def test_unavailable_database_server_reports_degraded_and_503(test_env):
    """Test that an unavailable database endpoint returns HTTP 503 and health reports degraded."""
    # Point engine to an unreachable database port
    unreachable_url = "mysql+pymysql://user:pass@127.0.0.1:59999/nonexistent?connect_timeout=1"
    bad_engine = create_db_engine(unreachable_url)
    
    orig_engine = config.DATABASE_URL
    set_engine(bad_engine)

    try:
        client = test_env["client"]
        health = client.get("/api/health").json()
        assert health["status"] == "degraded"
        assert health["db_accessible"] is False

        # Attempt to access evidence route when DB is down -> 503 Service Unavailable
        resp = client.get("/api/evidence")
        assert resp.status_code == 503
        assert "unavailable" in resp.json()["detail"].lower()
    finally:
        # Restore test engine
        set_engine(test_env["engine"])

def test_idempotent_sqlite_to_sql_migration(test_env):
    """Test SQLite to MySQL migration utility idempotency, record preservation, and verification."""
    temp_dir = test_env["temp_dir"]
    src_sqlite = temp_dir / "migration_src.db"
    dest_sqlite = temp_dir / "migration_dest.db"

    # 1. Create source SQLite database with mock forensic evidence
    src_engine = create_db_engine(f"sqlite:///{src_sqlite.as_posix()}")
    init_db(src_engine)

    set_engine(src_engine)
    session = get_session_factory()()

    ev1 = EvidenceModel(
        id="ev-mig-01",
        case_id="CASE_MIG_01",
        filename="can_test.log",
        storage_filename="ev-mig-01_can_test.log",
        file_size=1024,
        mime_type="text/plain",
        evidence_type="CAN_BUS_DUMP",
        sha256="a" * 64,
        trusted_reference="a" * 64,
        status="VERIFIED",
        investigator_id="Det_Smith"
    )
    session.add(ev1)
    session.commit()

    evt1 = AuditLogModel(
        event_id="evt-mig-01",
        evidence_id="ev-mig-01",
        event_type="INGESTION",
        actor_id="Det_Smith",
        details="Ingestion of mock migration test evidence",
        verification_result="VERIFIED",
        previous_hash="0" * 64,
        record_hash="b" * 64
    )
    session.add(evt1)
    session.commit()
    session.close()

    # 2. Run first migration pass
    target_url = f"sqlite:///{dest_sqlite.as_posix()}"
    res1 = run_migration(sqlite_path=src_sqlite, target_url=target_url, dry_run=False)
    assert res1["evidence_imported"] == 1
    assert res1["audit_imported"] == 1
    assert res1["evidence_skipped"] == 0

    # 3. Run second migration pass (idempotency check)
    res2 = run_migration(sqlite_path=src_sqlite, target_url=target_url, dry_run=False)
    assert res2["evidence_imported"] == 0
    assert res2["evidence_skipped"] == 1
    assert res2["audit_imported"] == 0
    assert res2["audit_skipped"] == 1
    assert res2["target_evidence_count"] == 1
    assert res2["target_audit_count"] == 1

    # Restore test engine
    set_engine(test_env["engine"])
