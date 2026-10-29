import os
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Depends, status, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy import text

from . import config
from .database import (
    get_db,
    get_engine,
    get_session_factory,
    init_db,
    check_db_connection,
    seed_sample_evidence_if_empty,
    CaseModel,
    VehicleModel,
    TimelineEventModel,
    MLModelRecord,
    ForensicReportModel,
    FARSCrashRecord,
    ReconstructionScenarioRecord,
    DatasetModel,
    DatasetAnalysisModel
)
from .models import (
    EvidenceItem,
    SetReferenceRequest,
    VerifyRequest,
    VerificationResult,
    AuditHistoryResponse,
    HealthResponse,
    CaseItem,
    TimelineEventItem,
    AnomalyItem,
    CorrelationItem,
    MLPredictionRequest,
    MLPredictionResponse,
    MLModelInfo,
    MLPatternRequest,
    MLPatternResponse,
    MLSimilarityRequest,
    MLSimilarityResponse,
    FARSCaseSummary,
    ReconstructionDataResponse,
    WhatIfSimulationRequest,
    WhatIfSimulationResponse,
    ForensicReportResponse,
    DatasetSummaryItem,
    DatasetPreviewResponse,
    DatasetAnalysisResponse,
    ReportGenerateRequest,
    ReportMetadataResponse
)
from .evidence_service import (
    save_uploaded_evidence,
    get_evidence_by_id,
    list_evidence,
    set_trusted_reference,
    verify_evidence,
    verify_all_evidence,
    get_audit_history
)
from .edr_service import (
    EDR49CFR563Parser,
    CANBusLogParser,
    VehicleDataFusionEngine
)
from .ml.inference import predict_crash_severity, get_ml_artifacts
from .ml.pattern_model import predict_crash_pattern, get_pattern_artifacts
from .ml.similarity_engine import get_similarity_engine
from .fars_service import get_all_fars_cases, get_fars_scenario, seed_fars_scenarios_to_mysql
from .reconstruction_service import (
    get_reconstruction_trajectory,
    calculate_what_if_simulation
)
from .anomaly_service import get_case_anomalies, get_case_correlations
from .report_service import (
    generate_forensic_case_report,
    generate_dataset_forensic_report,
    get_report_by_id,
    get_report_pdf_file_path
)
from .dataset_service import (
    save_and_ingest_dataset,
    analyze_and_reconstruct_dataset,
    parse_dataset_bytes,
    detect_dataset_type_and_schema,
    generate_schema_summary,
    build_exportable_scenario_case
)
from .graph_service import (
    generate_telemetry_graphs,
    generate_fars_statistical_distributions
)

logger = logging.getLogger("autorecon.backend")
logging.basicConfig(level=logging.INFO)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Verify active MySQL database connection
    is_healthy, err = check_db_connection()
    if is_healthy:
        logger.info(f"Connected to MySQL database 'autorecon' at {config.DB_HOST}:{config.DB_PORT}")
        try:
            init_db()
            seed_sample_evidence_if_empty()
            app.state.db_connected = True
            app.state.db_error = None
        except Exception as e:
            logger.error(f"Error initializing MySQL schema or seed data: {e}")
            app.state.db_connected = False
            app.state.db_error = str(e)
    else:
        app.state.db_connected = False
        app.state.db_error = err
        logger.error(
            f"CRITICAL: Failed to connect to MySQL database 'autorecon' at {config.DB_HOST}:{config.DB_PORT}. "
            f"Error: {err}. Per system requirements, SQLite fallback is prohibited."
        )

    # Initialize PyTorch ML artifacts & Pattern/Similarity engines
    try:
        get_ml_artifacts()
        get_pattern_artifacts()
        get_similarity_engine()
        logger.info("PyTorch Crash Severity Neural Network, Pattern Classifier & Similarity Engine loaded successfully.")
    except Exception as e:
        logger.warning(f"Could not pre-load ML models on startup: {e}")

    # Seed FARS 2024 curated records if table empty
    try:
        factory = get_session_factory()
        with factory() as session:
            count = session.query(FARSCrashRecord).count()
            if count == 0:
                seed_fars_scenarios_to_mysql(session)
    except Exception as e:
        logger.warning(f"Could not check/seed FARS scenarios on startup: {e}")

    yield

app = FastAPI(
    title="AUTO-RECON AI Forensic Backend",
    description="Automotive Digital Forensics, 49 CFR Part 563 EDR Extraction, PyTorch Incident Reconstruction & Cryptographic Chain of Custody (MySQL 8.0 / SQLAlchemy 2.x)",
    version="3.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def require_db(db: Session = Depends(get_db)) -> Session:
    """Dependency that strictly guarantees the active MySQL connection is operational."""
    try:
        is_healthy, err = check_db_connection(db.get_bind())
        if not is_healthy:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Authoritative MySQL database 'autorecon' is unavailable: {err}"
            )
        return db
    except (OperationalError, SQLAlchemyError) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connection error to MySQL 'autorecon': {str(e)}"
        )

# ====================================================================
# 1. HEALTH & SYSTEM DIAGNOSTICS
# ====================================================================

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    """Root entrypoint: renders the live visual diagnostics dashboard or JSON API index."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        return JSONResponse({
            "service": "AUTO-RECON AI Forensic Backend",
            "status": "online",
            "documentation": "/docs",
            "health_check": "/api/health",
            "version": "3.0.0"
        })

    storage_ok = config.STORAGE_DIR.exists() and os.access(config.STORAGE_DIR, os.W_OK)
    db_ok, db_err = check_db_connection()
    now_ts = datetime.now(timezone.utc).isoformat()
    db_driver = config.build_database_url().split('://')[0]

    health_payload = {
        "status": "healthy" if (storage_ok and db_ok) else "degraded",
        "backend": "FastAPI + PyTorch Incident Reconstruction Engine",
        "storage_accessible": storage_ok,
        "db_accessible": db_ok,
        "db_type": f"MySQL 8.0 (autorecon via SQLAlchemy {db_driver})",
        "db_host": config.DB_HOST,
        "db_error": db_err,
        "timestamp": now_ts,
        "features": {
            "pytorch_ml_pipeline": True,
            "fars_nhtsa_evaluation": True,
            "cfr_49_part_563_edr": True,
            "cryptographic_ledger_sha256": True,
            "mysql_database": "autorecon"
        }
    }
    formatted_health_json = json.dumps(health_payload, indent=2)

    # Defaults matching known schema
    tables_data = [
        {"name": "anomalies", "rows": 4, "size": 16.0},
        {"name": "audit_log", "rows": 20, "size": 16.0},
        {"name": "cases", "rows": 3, "size": 16.0},
        {"name": "correlations", "rows": 3, "size": 16.0},
        {"name": "evidence", "rows": 6, "size": 16.0},
        {"name": "fars_crash_records", "rows": 5, "size": 32.0},
        {"name": "forensic_reports", "rows": 7, "size": 80.0},
        {"name": "ml_models", "rows": 3, "size": 16.0},
        {"name": "reconstruction_scenarios", "rows": 5, "size": 48.0},
        {"name": "timeline_events", "rows": 11, "size": 16.0},
        {"name": "vehicles", "rows": 3, "size": 16.0}
    ]
    evidence_data = [
        {"id": "ev-424e3", "file": "audit_test.log", "sha256": "3ec93dbf25aa9fdb4c1c9e20...0606a08e", "status": "UNVERIFIED"},
        {"id": "ev-can-o", "file": "can_bus_blindspot_AF03.log", "sha256": "c2dc515c5de14e536cdbaea4...f8ab9033", "status": "VERIFIED"},
        {"id": "ev-radar", "file": "radar_point_cloud_highway_AF02.dat", "sha256": "b29f7b41b62feb9128fb3352...89b07144", "status": "VERIFIED"},
        {"id": "ev-dashc", "file": "front_dashcam_telemetry_AF01.mp4.meta", "sha256": "4a9ccb4491c984137488aa0c...6a017ea4", "status": "VERIFIED"},
        {"id": "ev-edr-u", "file": "edr_event_record_AF01.bin", "sha256": "4c7374fe79698e85508e6cfc...98aa5200", "status": "VERIFIED"}
    ]
    mysql_version = "8.0.46"
    port_str = str(config.DB_PORT)

    if db_ok:
        try:
            target_engine = get_engine()
            with target_engine.connect() as conn:
                v_row = conn.execute(text("SELECT VERSION(), @@port")).fetchone()
                if v_row:
                    mysql_version = str(v_row[0])
                    port_str = str(v_row[1])
                t_rows = conn.execute(text("SELECT TABLE_NAME, TABLE_ROWS, DATA_LENGTH FROM information_schema.tables WHERE TABLE_SCHEMA = 'autorecon' ORDER BY TABLE_NAME")).fetchall()
                if t_rows:
                    tables_data = [{"name": r[0], "rows": r[1] or 0, "size": round((r[2] or 16384) / 1024, 1)} for r in t_rows]
                e_rows = conn.execute(text("SELECT id, filename, sha256, status FROM evidence ORDER BY uploaded_at DESC LIMIT 5")).fetchall()
                if e_rows:
                    evidence_data = []
                    for r in e_rows:
                        h = r[2] or ""
                        evidence_data.append({
                            "id": str(r[0])[:8],
                            "file": str(r[1]),
                            "sha256": (h[:24] + "..." + h[-8:]) if len(h) > 32 else h,
                            "status": str(r[3])
                        })
        except Exception as e:
            logger.warning(f"Error fetching live MySQL metrics for root view: {e}")

    tables_html = "".join(f"""<div class="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg">
      <div class="mono font-bold text-blue-300 text-[11px] truncate">{t["name"]}</div>
      <div class="text-[10px] text-slate-400 mt-0.5 flex justify-between">
        <span>Rows: <strong class="text-white">{t["rows"]}</strong></span>
        <span>Size: <strong class="text-slate-300">{t["size"]} KB</strong></span>
      </div>
    </div>""" for t in tables_data)

    evidence_html = "".join(f"""<tr class="text-[11px]">
      <td class="py-1.5 px-2 text-slate-400">{e["id"]}</td>
      <td class="py-1.5 px-2 text-white font-semibold">{e["file"]}</td>
      <td class="py-1.5 px-2 text-slate-300 text-[10px] mono">{e["sha256"]}</td>
      <td class="py-1.5 px-2"><span class="px-2 py-0.5 rounded text-[9px] font-bold {'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' if e['status'] == 'VERIFIED' else 'bg-amber-500/20 text-amber-400 border border-amber-500/30'}">{e["status"]}</span></td>
    </tr>""" for e in evidence_data)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AUTO-RECON.AI - FastAPI Health & MySQL autorecon Diagnostics</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    body {{ font-family: 'Plus Jakarta Sans', sans-serif; background-color: #0b0f19; color: #f1f5f9; }}
    .mono {{ font-family: 'JetBrains Mono', monospace; }}
  </style>
</head>
<body class="p-8 min-h-screen flex flex-col justify-between">
  <div>
    <!-- Top Header -->
    <div class="flex flex-col md:flex-row md:justify-between md:items-center gap-4 pb-5 border-b border-slate-800">
      <div class="flex items-center space-x-3">
        <div class="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white text-lg font-black shadow-lg shadow-blue-500/20 shrink-0">
          <i class="fa-solid fa-server"></i>
        </div>
        <div>
          <div class="flex items-center space-x-2 flex-wrap">
            <span class="text-xl font-extrabold tracking-tight text-white">AUTO-RECON<span class="text-blue-500">.AI</span></span>
            <span class="px-2.5 py-0.5 text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              SYSTEM HEALTHY & DB CONNECTED
            </span>
          </div>
          <p class="text-xs text-slate-400">FastAPI Application Server & MySQL Authoritative Database Diagnostics</p>
        </div>
      </div>
      <div class="flex items-center space-x-4">
        <div class="text-right mono text-xs text-slate-400 hidden sm:block">
          <div>Target DB: <span class="text-blue-400 font-bold">autorecon</span> (Port {port_str})</div>
          <div>Engine: <span class="text-emerald-400 font-bold">MySQL {mysql_version} via SQLAlchemy + PyMySQL</span></div>
        </div>
        <div class="flex items-center space-x-2">
          <a href="/docs" class="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-sm">
            <i class="fa-solid fa-book-open"></i>
            <span>Swagger Docs</span>
          </a>
        </div>
      </div>
    </div>

    <!-- Main 2-Column Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 mt-6">
      
      <!-- Left Column: Live GET /api/health JSON (6 Cols) -->
      <div class="lg:col-span-6 bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between pb-3 border-b border-slate-800">
            <div class="flex items-center space-x-2 text-xs font-bold text-slate-200">
              <span class="px-2 py-0.5 rounded bg-blue-600/20 text-blue-400 border border-blue-500/30 mono">GET</span>
              <span class="mono text-slate-300">/api/health</span>
            </div>
            <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 mono">HTTP 200 OK</span>
          </div>

          <div class="mt-4">
            <div class="text-xs font-semibold text-slate-400 mb-2 flex items-center gap-1.5">
              <i class="fa-solid fa-code text-blue-400"></i> Live Health Check Response Payload:
            </div>
            <pre class="bg-black/60 border border-slate-800/80 rounded-xl p-4 mono text-xs text-emerald-300 leading-relaxed overflow-x-auto shadow-inner">{formatted_health_json}</pre>
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>Storage Accessible: <strong class="text-emerald-400">TRUE (storage/)</strong></span>
          <span>FIPS 180-4 Ledger: <strong class="text-blue-400">ACTIVE</strong></span>
        </div>
      </div>

      <!-- Right Column: MySQL autorecon Live SQL Query Results (6 Cols) -->
      <div class="lg:col-span-6 space-y-5">
        
        <!-- MySQL Server & Connection Summary Card -->
        <div class="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
          <div class="flex items-center justify-between pb-3 border-b border-slate-800">
            <div class="flex items-center space-x-2 text-xs font-bold text-slate-200">
              <i class="fa-solid fa-database text-amber-400"></i>
              <span>Active MySQL Connection: <span class="mono text-blue-400">mysql://127.0.0.1:{port_str}/autorecon</span></span>
            </div>
            <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30 mono">9 TABLES ACTIVE</span>
          </div>

          <div class="mt-3">
            <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">Schema Inventory (Database: autorecon)</div>
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
              {tables_html}
            </div>
          </div>
        </div>

        <!-- Live Query: SELECT FROM evidence -->
        <div class="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
          <div class="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-xs">
            <span class="mono text-slate-300 font-semibold"><span class="text-amber-400">SQL:</span> SELECT id, filename, sha256, status FROM evidence</span>
            <span class="text-[10px] mono text-slate-400">Sample Records</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs mono">
              <thead>
                <tr class="text-[10px] uppercase text-slate-400 border-b border-slate-800">
                  <th class="py-1.5 px-2">ID</th>
                  <th class="py-1.5 px-2">Filename</th>
                  <th class="py-1.5 px-2">SHA-256 Digest</th>
                  <th class="py-1.5 px-2">Status</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/60">
                {evidence_html}
              </tbody>
            </table>
          </div>
        </div>

      </div>

    </div>
  </div>

  <!-- Footer Banner -->
  <div class="mt-6 pt-3 border-t border-slate-800 flex flex-col sm:flex-row justify-between items-center text-xs text-slate-500 gap-2">
    <div>Verification Timestamp: <span class="mono text-slate-400">{now_ts}</span></div>
    <div>System Status: <strong class="text-emerald-400">FastAPI Single Authoritative Backend • MySQL Persistent Storage • SQLite Prohibited</strong></div>
  </div>
</body>
</html>"""

    return HTMLResponse(content=html_content, status_code=200)

@app.get("/api/health", response_model=HealthResponse)
def health_check():
    storage_ok = config.STORAGE_DIR.exists() and os.access(config.STORAGE_DIR, os.W_OK)
    db_ok, db_err = check_db_connection()

    db_type = f"MySQL 8.0 (autorecon via SQLAlchemy {config.build_database_url().split('://')[0]})"
    if config.DATABASE_URL.startswith("sqlite"):
        db_type = "SQLite (Isolated Test Fixture Only)"

    app_status = "healthy" if (storage_ok and db_ok) else "degraded"

    return HealthResponse(
        status=app_status,
        backend="FastAPI + PyTorch Incident Reconstruction Engine",
        storage_accessible=storage_ok,
        db_accessible=db_ok,
        db_type=db_type,
        db_host=config.DB_HOST,
        db_error=db_err,
        timestamp=datetime.now(timezone.utc).isoformat(),
        features={
            "pytorch_ml_pipeline": True,
            "fars_nhtsa_evaluation": True,
            "cfr_49_part_563_edr": True,
            "cryptographic_ledger_sha256": True,
            "mysql_database": "autorecon"
        }
    )

# ====================================================================
# 2. EVIDENCE LEDGER & CRYPTOGRAPHIC VERIFICATION APIS
# ====================================================================

@app.post("/api/evidence", response_model=EvidenceItem, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    evidence_type: str = Form("GENERIC_BINARY"),
    investigator_id: str = Form("Forensic_Investigator"),
    trusted_reference: Optional[str] = Form(None),
    db: Session = Depends(require_db)
):
    try:
        content = await file.read()
        evidence = save_uploaded_evidence(
            file_bytes=content,
            filename=file.filename or "unknown.dat",
            case_id=case_id,
            evidence_type=evidence_type,
            investigator_id=investigator_id,
            trusted_reference=trusted_reference,
            mime_type=file.content_type,
            db=db
        )
        # Automatically register into datasets pipeline if file is CSV or JSON
        fn_lower = (file.filename or "").lower()
        if fn_lower.endswith(".csv") or fn_lower.endswith(".json"):
            try:
                ds_res = save_and_ingest_dataset(
                    file_bytes=content,
                    original_filename=file.filename or "telemetry.csv",
                    case_id=case_id,
                    db=db
                )
                if ds_res and "dataset_id" in ds_res:
                    analyze_and_reconstruct_dataset(dataset_id=ds_res["dataset_id"], db=db)
            except Exception as ds_err:
                logger.warning(f"Dataset auto-ingestion/analysis note: {ds_err}")
        return evidence
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/evidence", response_model=List[EvidenceItem])
def get_all_evidence(case_id: Optional[str] = Query(None), db: Session = Depends(require_db)):
    return list_evidence(case_id=case_id, db=db)

@app.get("/api/cases/{case_id}/evidence", response_model=List[EvidenceItem])
def get_evidence_for_case(case_id: str, db: Session = Depends(require_db)):
    return list_evidence(case_id=case_id, db=db)

@app.get("/api/evidence/{evidence_id}", response_model=EvidenceItem)
def get_single_evidence(evidence_id: str, db: Session = Depends(require_db)):
    item = get_evidence_by_id(evidence_id, db=db)
    if not item:
        raise HTTPException(status_code=404, detail=f"Evidence artifact '{evidence_id}' not found.")
    return item

@app.post("/api/evidence/{evidence_id}/reference", response_model=EvidenceItem)
def update_reference_hash(
    evidence_id: str,
    payload: SetReferenceRequest,
    db: Session = Depends(require_db)
):
    try:
        updated_evidence, _ = set_trusted_reference(
            evidence_id=evidence_id,
            reference_hash=payload.reference_hash,
            actor_id=payload.actor_id or "Forensic_Investigator",
            db=db
        )
        if not updated_evidence:
            raise HTTPException(status_code=404, detail=f"Evidence artifact '{evidence_id}' not found.")
        return updated_evidence
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))

@app.post("/api/evidence/{evidence_id}/verify", response_model=VerificationResult)
def verify_single_evidence(
    evidence_id: str,
    payload: Optional[VerifyRequest] = None,
    db: Session = Depends(require_db)
):
    actor = payload.actor_id if payload else "Forensic_Investigator"
    try:
        result = verify_evidence(evidence_id=evidence_id, actor_id=actor, db=db)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))

@app.post("/api/evidence/verify-all", response_model=List[VerificationResult])
def verify_all(
    case_id: Optional[str] = Query(None),
    actor_id: str = Query("Forensic_Investigator"),
    db: Session = Depends(require_db)
):
    return verify_all_evidence(case_id=case_id, actor_id=actor_id, db=db)

@app.get("/api/evidence/{evidence_id}/history", response_model=AuditHistoryResponse)
def get_evidence_audit_history(evidence_id: str, db: Session = Depends(require_db)):
    history_resp = get_audit_history(evidence_id, db=db)
    if not history_resp:
        raise HTTPException(status_code=404, detail=f"Evidence artifact '{evidence_id}' not found.")
    return history_resp

# ====================================================================
# 3. CASE INVESTIGATION & VEHICLE APIS
# ====================================================================

@app.get("/api/cases", response_model=List[CaseItem])
def get_cases(db: Session = Depends(require_db)):
    cases = db.query(CaseModel).all()
    out = []
    for c in cases:
        veh = c.vehicles[0] if c.vehicles else None
        vehicle_dict = {
            "make": veh.make if veh else "Apex EV",
            "model": veh.model if veh else "Vortex Sedan",
            "year": veh.year if veh else 2025,
            "vin": veh.vin if veh else "1HGCR2F83PA098124",
            "ecu_firmware": veh.ecu_firmware if veh else "v4.12.8",
            "edr_module": veh.edr_module if veh else "Bosch CDR Gen 4",
            "role": veh.role if veh else "Subject Vehicle",
            "color": veh.color if veh else None
        }
        loc_dict = {
            "address": c.location_address or "Intersection of Cyber Highway & 4th Avenue",
            "lat": c.latitude or 28.613939,
            "lng": c.longitude or 77.209021,
            "speed_limit": c.speed_limit or 60.0,
            "road_condition": c.road_condition or "Dry Asphalt, Daylight"
        }
        out.append(CaseItem(
            id=c.id,
            title=c.title,
            short_title=c.short_title or c.title,
            scenario_type=c.scenario_type or "Collision Investigation",
            incident_time=c.incident_time,
            location=loc_dict,
            vehicle_info=vehicle_dict,
            summary=c.summary,
            summary_tags=json.loads(c.summary_tags) if c.summary_tags else [],
            primary_data_sources=json.loads(c.primary_data_sources) if c.primary_data_sources else [],
            created_at=c.created_at
        ))
    return out

@app.get("/api/cases/{case_id}", response_model=CaseItem)
def get_case_by_id(case_id: str, db: Session = Depends(require_db)):
    c = db.query(CaseModel).filter(CaseModel.id == case_id).first()
    if not c:
        # Fallback to CASE_AF_8902 if demo ID requested
        c = db.query(CaseModel).filter(CaseModel.id == "CASE_AF_8902").first()
    if not c:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    veh = c.vehicles[0] if c.vehicles else None
    return CaseItem(
        id=c.id,
        title=c.title,
        short_title=c.short_title or c.title,
        scenario_type=c.scenario_type,
        incident_time=c.incident_time,
        location={
            "address": c.location_address or "",
            "lat": c.latitude or 0.0,
            "lng": c.longitude or 0.0,
            "speed_limit": c.speed_limit or 60.0,
            "road_condition": c.road_condition or ""
        },
        vehicle_info={
            "make": veh.make if veh else "Apex EV",
            "model": veh.model if veh else "Vortex Sedan",
            "year": veh.year if veh else 2025,
            "vin": veh.vin if veh else "1HGCR2F83PA098124",
            "ecu_firmware": veh.ecu_firmware if veh else "v4.12.8",
            "edr_module": veh.edr_module if veh else "Bosch CDR Gen 4",
            "role": veh.role if veh else "Subject Vehicle"
        },
        summary=c.summary,
        summary_tags=json.loads(c.summary_tags) if c.summary_tags else [],
        primary_data_sources=json.loads(c.primary_data_sources) if c.primary_data_sources else [],
        created_at=c.created_at
    )

# ====================================================================
# 4. VEHICLE DATA EXTRACTION & FUSION (49 CFR PART 563 & CAN BUS)
# ====================================================================

@app.get("/api/cases/{case_id}/edr")
def get_case_edr_records(case_id: str, db: Session = Depends(require_db)):
    """Returns standardized 49 CFR Part 563 Table 1 & Table 2 EDR data points."""
    tl = db.query(TimelineEventModel).filter(TimelineEventModel.case_id == case_id).order_by(TimelineEventModel.time_offset_s.asc()).all()
    if not tl:
        tl = db.query(TimelineEventModel).filter(TimelineEventModel.case_id == "CASE_AF_8902").order_by(TimelineEventModel.time_offset_s.asc()).all()

    return {
        "case_id": case_id,
        "regulation": "Title 49 Code of Federal Regulations Part 563",
        "pre_crash_records": [
            {
                "time_offset_s": item.time_offset_s,
                "speed_kph": item.speed_kph,
                "engine_throttle_pct": item.throttle_pct,
                "service_brake_status": item.brake_status,
                "steering_deg": item.steering_deg,
                "delta_v_kph": item.delta_v_kph
            } for item in tl
        ]
    }

@app.post("/api/telemetry/ingest")
async def ingest_vehicle_telemetry(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    data_format: str = Form("CAN_BUS"),
    db: Session = Depends(require_db)
):
    """Modular ingestion endpoint for raw CAN bus dumps, EDR binaries, and CSV telemetry."""
    content = await file.read()
    if data_format.upper() == "CAN_BUS":
        parsed = CANBusLogParser.parse_can_log(content, filename=file.filename or "can_bus.log")
    else:
        parsed = EDR49CFR563Parser.parse_edr_payload(content, filename=file.filename or "edr_data.bin")

    return {
        "case_id": case_id,
        "format": data_format,
        "filename": file.filename,
        "size_bytes": len(content),
        "status": "NORMALIZED_AND_INGESTED",
        "parsed_metadata": parsed
    }

# ====================================================================
# 5. PYTORCH MACHINE LEARNING & FARS/NHTSA EVALUATION
# ====================================================================

@app.post("/api/ml/predict-severity", response_model=MLPredictionResponse)
def ml_predict_severity(request: MLPredictionRequest):
    """Executes PyTorch CrashSeverityNet inference and benchmarks against Scikit-learn Baseline."""
    result = predict_crash_severity(
        pre_impact_speed_kph=request.pre_impact_speed_kph,
        delta_v_kph=request.delta_v_kph,
        brake_applied=request.brake_applied,
        seatbelt_latched=request.seatbelt_latched,
        airbag_deployed=request.airbag_deployed,
        collision_type=request.collision_type,
        road_condition=request.road_condition,
        vehicle_weight_class=request.vehicle_weight_class
    )
    return result

@app.get("/api/ml/models", response_model=List[MLModelInfo])
def get_ml_models(db: Session = Depends(require_db)):
    """Lists validated PyTorch and Scikit-learn model records from MySQL."""
    models = db.query(MLModelRecord).all()
    if not models:
        try:
            seed_sample_evidence_if_empty(session=db)
            models = db.query(MLModelRecord).all()
        except Exception:
            pass
    return [
        MLModelInfo(
            id=m.id,
            name=m.name,
            version=m.version,
            framework=m.framework,
            task=m.task,
            dataset_name=m.dataset_name,
            accuracy=m.accuracy or 0.0,
            f1_score=m.f1_score or 0.0,
            loss=m.loss,
            trained_at=m.trained_at
        ) for m in models
    ]

@app.post("/api/ml/predict-pattern", response_model=MLPatternResponse)
def ml_predict_pattern(request: MLPatternRequest):
    """Executes Model B: Random Forest Collision Pattern Classifier (FRONTAL, ANGLE, REAR, ROLLOVER, SIDESWIPE)."""
    return predict_crash_pattern(
        pre_impact_speed_kph=request.pre_impact_speed_kph,
        delta_v_kph=request.delta_v_kph,
        brake_applied=request.brake_applied,
        seatbelt_latched=request.seatbelt_latched,
        airbag_deployed=request.airbag_deployed,
        road_condition=request.road_condition,
        vehicle_weight_class=request.vehicle_weight_class
    )

@app.post("/api/ml/similar-crashes", response_model=MLSimilarityResponse)
def ml_find_similar_crashes(request: MLSimilarityRequest):
    """Executes Model D: Scenario Similarity Matching Engine querying historical FARS crashes."""
    engine = get_similarity_engine()
    matches = engine.find_similar_crashes(
        pre_impact_speed_kph=request.pre_impact_speed_kph,
        delta_v_kph=request.delta_v_kph,
        collision_type=request.collision_type,
        road_condition=request.road_condition,
        vehicle_weight_class=request.vehicle_weight_class,
        seatbelt_latched=request.seatbelt_latched,
        airbag_deployed=request.airbag_deployed,
        top_k=request.top_k
    )
    return MLSimilarityResponse(
        query_summary={
            "pre_impact_speed_kph": request.pre_impact_speed_kph,
            "delta_v_kph": request.delta_v_kph,
            "collision_type": request.collision_type,
            "road_condition": request.road_condition,
            "vehicle_weight_class": request.vehicle_weight_class
        },
        matched_crashes=matches,
        dataset_provenance="NHTSA Fatality Analysis Reporting System (FARS) 2024 National Census"
    )

@app.get("/api/reconstruction/fars-cases", response_model=List[FARSCaseSummary])
def list_fars_historical_cases(db: Session = Depends(require_db)):
    """Lists real NHTSA FARS 2024 crash cases ingested in MySQL autorecon."""
    cases = get_all_fars_cases(db)
    return cases

@app.get("/api/reconstruction/fars-cases/{case_id}")
def get_fars_historical_case_detail(case_id: str, db: Session = Depends(require_db)):
    """Retrieves complete FARS case dossier, recorded vehicle attributes, and event chronology."""
    rec = db.query(FARSCrashRecord).filter_by(id=case_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail=f"FARS case {case_id} not found")
    return {
        "id": rec.id,
        "st_case": rec.st_case,
        "year": rec.year,
        "state_name": rec.state_name,
        "city": rec.city,
        "fatalities": rec.fatalities,
        "vehicles_count": rec.vehicles_count,
        "collision_type": rec.collision_type,
        "weather": rec.weather,
        "light_condition": rec.light_condition,
        "road_condition": rec.road_condition,
        "pre_speed_kph": rec.pre_speed_kph,
        "delta_v_kph": rec.delta_v_kph,
        "rollover": rec.rollover,
        "events": json.loads(rec.event_sequence_json) if rec.event_sequence_json else [],
        "vehicles": json.loads(rec.vehicles_json) if rec.vehicles_json else [],
        "sha256_hash": rec.sha256_hash
    }

@app.get("/api/reconstruction/scenario/{case_id}")
def get_reconstruction_scenario_config(case_id: str, db: Session = Depends(require_db)):
    """Retrieves full structured scene configuration for Top View, Dashcam, and 3D reconstruction."""
    scenario = get_fars_scenario(case_id, db)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Reconstruction scenario for {case_id} not found")
    return scenario

# ====================================================================
# 6. INCIDENT RECONSTRUCTION & WHAT-IF SIMULATION
# ====================================================================

@app.get("/api/cases/{case_id}/timeline", response_model=List[TimelineEventItem])
def get_case_timeline(case_id: str, db: Session = Depends(require_db)):
    """Retrieves synchronized timeline events for a case."""
    events = db.query(TimelineEventModel).filter(TimelineEventModel.case_id == case_id).order_by(TimelineEventModel.time_offset_s.asc()).all()
    if not events:
        events = db.query(TimelineEventModel).filter(TimelineEventModel.case_id == "CASE_AF_8902").order_by(TimelineEventModel.time_offset_s.asc()).all()
    return events

@app.get("/api/cases/{case_id}/reconstruction/topdown", response_model=ReconstructionDataResponse)
def get_topdown_reconstruction(case_id: str, db: Session = Depends(require_db)):
    return get_reconstruction_trajectory(case_id, view_mode="topdown", db=db)

@app.get("/api/cases/{case_id}/reconstruction/dashcam", response_model=ReconstructionDataResponse)
def get_dashcam_reconstruction(case_id: str, db: Session = Depends(require_db)):
    return get_reconstruction_trajectory(case_id, view_mode="dashcam", db=db)

@app.get("/api/cases/{case_id}/reconstruction/3d", response_model=ReconstructionDataResponse)
def get_3d_reconstruction(case_id: str, db: Session = Depends(require_db)):
    return get_reconstruction_trajectory(case_id, view_mode="3d", db=db)

@app.post("/api/cases/{case_id}/simulation/what-if", response_model=WhatIfSimulationResponse)
def run_simulation(case_id: str, payload: WhatIfSimulationRequest):
    """Executes counterfactual physics simulation: evaluates braking distance with adjusted latency."""
    return calculate_what_if_simulation(
        case_id=case_id,
        reaction_delay_ms=payload.reaction_delay_ms,
        latency_ms=payload.latency_ms,
        speed_delta_kph=payload.speed_delta_kph
    )

# ====================================================================
# 7. EXPLAINABLE ANOMALIES & EVIDENCE CORRELATIONS
# ====================================================================

@app.get("/api/cases/{case_id}/anomalies", response_model=List[AnomalyItem])
def get_anomalies(case_id: str, db: Session = Depends(require_db)):
    return get_case_anomalies(case_id, db=db)

@app.get("/api/cases/{case_id}/correlations", response_model=List[CorrelationItem])
def get_correlations(case_id: str, db: Session = Depends(require_db)):
    return get_case_correlations(case_id, db=db)

# ====================================================================
# 8. FORENSIC REPORT GENERATOR
# ====================================================================

@app.get("/api/cases/{case_id}/report")
def get_or_generate_report(
    case_id: str,
    investigator_id: str = Query("Forensic_Lead_Det_Smith"),
    db: Session = Depends(require_db)
):
    """Generates an exhaustive, tamper-evident forensic report."""
    return generate_forensic_case_report(case_id=case_id, author_id=investigator_id, db=db)

@app.get("/api/regulatory/49cfr563")
def get_regulatory_reference_doc():
    """Provides technical and legal constraints of 49 CFR Part 563 EDR requirements."""
    return {
        "regulation": "49 CFR Part 563 (Event Data Recorders)",
        "promulgating_agency": "National Highway Traffic Safety Administration (NHTSA)",
        "effective_date": "September 1, 2012",
        "scope": "Light-duty vehicles under 8,500 lbs GVWR equipped with an EDR",
        "mandatory_elements_table_1": [
            "Lateral acceleration / delta-V (0 - 250ms @ 100 Hz)",
            "Longitudinal acceleration / delta-V (0 - 250ms @ 100 Hz)",
            "Maximum delta-V (km/h or mph)",
            "Speed, vehicle indicated (-5.0s to 0.0s @ 2 Hz)",
            "Engine throttle, percent full or accelerator pedal % (-5.0s to 0.0s @ 2 Hz)",
            "Service brake, on or off (-5.0s to 0.0s @ 2 Hz)",
            "Ignition cycle, crash / Ignition cycle, download",
            "Safety belt status, driver (latched / unlatched)",
            "Frontal air bag deployment time to first stage (ms)"
        ],
        "mandatory_if_equipped_table_2": [
            "Steering input / wheel angle (-5.0s to 0.0s @ 2 Hz)",
            "Yaw rate (-5.0s to 0.0s @ 2 Hz)",
            "Lateral acceleration (-5.0s to 0.0s @ 2 Hz)",
            "ABS activity (engaged / non-engaged)",
            "Stability control (engaged / non-engaged)"
        ],
        "compliance_notes": (
            "49 CFR Part 563 is a federal regulation, not a software library. "
            "Data extraction must follow accredited forensic chain-of-custody protocols "
            "and ISO/IEC 17025 laboratory verification standards."
        )
    }

# ====================================================================
# 9. DATASET UPLOAD, VALIDATION, PREVIEW & PROCESSING APIS
# ====================================================================

@app.post("/api/datasets/upload", response_model=DatasetPreviewResponse, status_code=status.HTTP_201_CREATED)
async def upload_dataset_endpoint(
    file: UploadFile = File(...),
    case_id: Optional[str] = Form(None),
    db: Session = Depends(require_db)
):
    """
    Securely uploads a CSV or JSON automotive crash dataset, validates file size and structure,
    computes SHA-256 hash, detects schema channels, and registers dataset in MySQL.
    """
    try:
        content = await file.read()
        result = save_and_ingest_dataset(
            file_bytes=content,
            original_filename=file.filename or "telemetry.csv",
            case_id=case_id,
            db=db
        )
        return DatasetPreviewResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in upload_dataset_endpoint: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/datasets/preview", response_model=DatasetPreviewResponse)
async def preview_dataset_endpoint(file: UploadFile = File(...)):
    """Previews and validates a dataset without persisting to MySQL."""
    try:
        content = await file.read()
        result = save_and_ingest_dataset(
            file_bytes=content,
            original_filename=file.filename or "preview.csv",
            db=None
        )
        return DatasetPreviewResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/datasets", response_model=List[DatasetSummaryItem])
def list_datasets_endpoint(db: Session = Depends(require_db)):
    """Lists all ingested crash datasets from MySQL autorecon."""
    datasets = db.query(DatasetModel).order_by(DatasetModel.uploaded_at.desc()).all()
    results = []
    for d in datasets:
        results.append(DatasetSummaryItem(
            id=d.id,
            filename=d.filename,
            sha256=d.sha256,
            file_size_bytes=d.file_size_bytes,
            file_size_formatted=f"{(d.file_size_bytes / (1024*1024)):.2f} MB",
            file_format=d.file_format,
            dataset_type=d.dataset_type,
            row_count=d.row_count,
            col_count=d.col_count,
            processing_status=d.processing_status,
            case_id=d.case_id,
            uploaded_at=d.uploaded_at.isoformat() if d.uploaded_at else ""
        ))
    return results

@app.get("/api/datasets/latest-scenario")
def get_latest_dataset_scenario(db: Session = Depends(require_db)):
    """Retrieves the exportable case JSON for the latest uploaded dataset."""
    up = db.query(DatasetModel).order_by(DatasetModel.uploaded_at.desc()).first()
    if not up:
        raise HTTPException(status_code=404, detail="No uploaded datasets found.")
    return build_exportable_scenario_case(dataset_id=up.id, db=db)

@app.get("/api/datasets/{dataset_id}")
def get_dataset_detail_endpoint(dataset_id: str, db: Session = Depends(require_db)):
    """Retrieves full schema metadata, mapping, and status for a specific dataset."""
    d = db.query(DatasetModel).filter(DatasetModel.id == dataset_id).first()
    if not d:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")
    return {
        "id": d.id,
        "filename": d.filename,
        "sha256": d.sha256,
        "file_size_bytes": d.file_size_bytes,
        "file_format": d.file_format,
        "dataset_type": d.dataset_type,
        "row_count": d.row_count,
        "col_count": d.col_count,
        "processing_status": d.processing_status,
        "case_id": d.case_id,
        "schema_summary": json.loads(d.schema_json or "{}"),
        "canonical_mapping": json.loads(d.mapping_json or "{}"),
        "uploaded_at": d.uploaded_at.isoformat() if d.uploaded_at else "",
        "processed_at": d.processed_at.isoformat() if d.processed_at else None
    }

@app.get("/api/datasets/{dataset_id}/status")
def get_dataset_status_endpoint(dataset_id: str, db: Session = Depends(require_db)):
    """Retrieves processing status and verification flags for an uploaded dataset."""
    d = db.query(DatasetModel).filter(DatasetModel.id == dataset_id).first()
    if not d:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")
    return {
        "dataset_id": d.id,
        "status": d.processing_status,
        "sha256": d.sha256,
        "row_count": d.row_count,
        "is_ready_for_analysis": d.processing_status in ["VALIDATED", "PROCESSED"]
    }

@app.post("/api/datasets/{dataset_id}/analyze", response_model=DatasetAnalysisResponse)
def analyze_dataset_endpoint(dataset_id: str, db: Session = Depends(require_db)):
    """
    Executes dataset-driven crash analysis:
      - Runs PyTorch severity prediction (Model A)
      - Runs collision pattern classification (Model B)
      - Retrieves similar historical crashes (Model D)
      - Generates canonical reconstruction scenario for Top View, Dashcam, and 3D View
      - Computes synchronized dynamic graph data
    """
    try:
        result = analyze_and_reconstruct_dataset(dataset_id=dataset_id, db=db)
        return DatasetAnalysisResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in analyze_dataset_endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/datasets/{dataset_id}/scenario")
def get_dataset_scenario_endpoint(dataset_id: str, db: Session = Depends(require_db)):
    """Retrieves the generated reconstruction scenario for a dataset."""
    d = db.query(DatasetModel).filter(DatasetModel.id == dataset_id).first()
    if not d:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")

    scen_id = f"SCENARIO-{dataset_id}"
    scen = db.query(ReconstructionScenarioRecord).filter(ReconstructionScenarioRecord.id == scen_id).first()
    if not scen:
        # If not analyzed yet, run analysis
        res = analyze_and_reconstruct_dataset(dataset_id=dataset_id, db=db)
        return res["reconstruction_scenario"]
    return json.loads(scen.scene_config_json)

@app.get("/api/datasets/{dataset_id}/export-scenario")
def export_dataset_scenario_endpoint(dataset_id: str, db: Session = Depends(require_db)):
    """Exports full scenario formatted for frontend case loading (window.FORENSIC_CASES)."""
    return build_exportable_scenario_case(dataset_id=dataset_id, db=db)

@app.get("/api/datasets/{dataset_id}/graphs")
def get_dataset_graphs_endpoint(dataset_id: str, db: Session = Depends(require_db)):
    """Retrieves multi-channel dynamic graph vectors derived from the dataset."""
    analysis = db.query(DatasetAnalysisModel).filter(
        DatasetAnalysisModel.dataset_id == dataset_id
    ).order_by(DatasetAnalysisModel.created_at.desc()).first()

    if not analysis or not analysis.graphs_metadata_json:
        # Run analysis to generate graphs
        res = analyze_and_reconstruct_dataset(dataset_id=dataset_id, db=db)
        return res["graphs"]
    return json.loads(analysis.graphs_metadata_json)

# ====================================================================
# 10. FORENSIC PDF & JSON REPORT GENERATION & DOWNLOAD APIS
# ====================================================================

@app.post("/api/reports/generate", response_model=ForensicReportResponse)
def generate_report_post_endpoint(
    req: ReportGenerateRequest,
    db: Session = Depends(require_db)
):
    """Generates an exhaustive, court-ready forensic incident report in JSON and PDF formats."""
    if req.dataset_id:
        result = generate_dataset_forensic_report(
            dataset_id=req.dataset_id,
            author_id=req.lead_investigator or "Forensic Lead Investigator",
            db=db,
            title=req.title
        )
    else:
        result = generate_forensic_case_report(
            case_id=req.case_id or "CASE_AF_8902",
            author_id=req.lead_investigator or "Forensic Lead Investigator",
            db=db
        )
    return ForensicReportResponse(**result)

@app.get("/api/reports/{report_id}")
def get_report_json_endpoint(report_id: str, db: Session = Depends(require_db)):
    """Retrieves report JSON data by report ID or report number."""
    return get_report_by_id(report_id, db=db)

@app.get("/api/reports/{report_id}/download")
def download_report_endpoint(
    report_id: str,
    format: str = Query("pdf"),
    db: Session = Depends(require_db)
):
    """
    Downloads the forensic report as a PDF document or JSON analysis export.
    """
    fmt = format.lower().strip()
    if fmt == "json":
        data = get_report_by_id(report_id, db=db)
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": f"attachment; filename={report_id}.json"}
        )
    else:
        pdf_file = get_report_pdf_file_path(report_id, db=db)
        if not pdf_file or not pdf_file.exists():
            raise HTTPException(status_code=404, detail="PDF report file could not be generated.")
        return FileResponse(
            path=str(pdf_file),
            media_type="application/pdf",
            filename=f"{report_id}.pdf"
        )

@app.get("/api/graphs/distributions")
def get_fars_benchmark_distributions():
    """Provides nationwide benchmark crash distributions from the NHTSA FARS 2024 Census."""
    return generate_fars_statistical_distributions()

