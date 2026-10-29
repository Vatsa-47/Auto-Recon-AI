import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, List
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from . import config
from .database import (
    get_db,
    init_db,
    check_db_connection,
    seed_sample_evidence_if_empty
)
from .models import (
    EvidenceItem,
    SetReferenceRequest,
    VerifyRequest,
    VerificationResult,
    AuditHistoryResponse,
    HealthResponse
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

logger = logging.getLogger("autorecon.backend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Check database connection upon startup
    is_healthy, err = check_db_connection()
    if is_healthy:
        logger.info(f"Database connected successfully: {config.get_database_url_safe()}")
        try:
            init_db()
            seed_sample_evidence_if_empty()
            app.state.db_connected = True
            app.state.db_error = None
        except Exception as e:
            logger.error(f"Error initializing database schema/seeds: {e}")
            app.state.db_connected = False
            app.state.db_error = str(e)
    else:
        app.state.db_connected = False
        app.state.db_error = err
        logger.warning(
            f"Database connection failed at {config.DB_HOST}:{config.DB_PORT}. "
            f"Target URL: {config.get_database_url_safe()}. Error: {err}"
        )
    yield

app = FastAPI(
    title="AUTO-RECON AI Forensic Backend",
    description="Cryptographic Evidence Verification and Hash-Linked Chain-of-Custody API (MySQL / SQLAlchemy 2.x)",
    version="2.1.0",
    lifespan=lifespan
)

# Configure CORS for local browser access and file:// origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def require_db(db: Session = Depends(get_db)) -> Session:
    """Dependency that ensures the database connection is operational."""
    try:
        is_healthy, err = check_db_connection(db.get_bind())
        if not is_healthy:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Database service unavailable: {err}"
            )
        return db
    except (OperationalError, SQLAlchemyError) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service connection error. Please verify MySQL server status."
        )

@app.get("/api/health", response_model=HealthResponse)
def health_check():
    storage_ok = config.STORAGE_DIR.exists() and os.access(config.STORAGE_DIR, os.W_OK)
    db_ok, db_err = check_db_connection()

    db_type = "MySQL (SQLAlchemy 2.x)"
    if config.DATABASE_URL.startswith("sqlite"):
        db_type = "SQLite (Isolated Test Backend)"

    app_status = "healthy" if (storage_ok and db_ok) else "degraded"

    return HealthResponse(
        status=app_status,
        backend="FastAPI Forensic Verification Engine",
        storage_accessible=storage_ok,
        db_accessible=db_ok,
        db_type=db_type,
        db_host=config.DB_HOST if not config.DATABASE_URL.startswith("sqlite") else "local_file",
        db_error=db_err,
        timestamp=datetime.now(timezone.utc).isoformat()
    )

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
