import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select

from . import config
from .database import (
    get_session_factory,
    EvidenceModel,
    AuditLogModel,
    log_audit_event,
    compute_record_hash,
    format_audit_timestamp
)
from .models import (
    EvidenceItem,
    VerificationResult,
    AuditLogEntry,
    AuditHistoryResponse,
    HEX64_REGEX
)

CHUNK_SIZE = 65536  # 64 KB

def calculate_file_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()

def sanitize_filename(filename: str) -> str:
    cleaned = re.sub(r"[^\w\-.]", "_", Path(filename).name)
    return cleaned if cleaned else "unnamed_evidence.bin"

def _resolve_session(db: Optional[Session] = None) -> Tuple[Session, bool]:
    if db is not None:
        return db, False
    factory = get_session_factory()
    return factory(), True

def save_uploaded_evidence(
    file_bytes: bytes,
    filename: str,
    case_id: str,
    evidence_type: str = "GENERIC_BINARY",
    investigator_id: str = "Forensic_Investigator",
    trusted_reference: Optional[str] = None,
    mime_type: Optional[str] = None,
    db: Optional[Session] = None,
    storage_dir: Optional[Path] = None
) -> EvidenceItem:
    target_storage = storage_dir or config.STORAGE_DIR
    target_storage.mkdir(parents=True, exist_ok=True)

    clean_name = sanitize_filename(filename)
    evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
    storage_filename = f"{evidence_id}_{clean_name}"
    storage_path = target_storage / storage_filename

    # Stream write while calculating SHA-256
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    computed_sha256 = hasher.hexdigest()
    file_size = len(file_bytes)

    with open(storage_path, "wb") as f:
        f.write(file_bytes)

    # Validate trusted reference if supplied
    normalized_ref = None
    if trusted_reference:
        ref_candidate = trusted_reference.strip().lower()
        if HEX64_REGEX.match(ref_candidate):
            normalized_ref = ref_candidate

    if normalized_ref:
        if computed_sha256 == normalized_ref:
            status = "VERIFIED"
        else:
            status = "MISMATCH"
    else:
        status = "UNVERIFIED"

    now_dt = datetime.now(timezone.utc)
    session, owns_session = _resolve_session(db)
    try:
        ev = EvidenceModel(
            id=evidence_id,
            case_id=case_id,
            filename=clean_name,
            storage_filename=storage_filename,
            file_size=file_size,
            mime_type=mime_type or "application/octet-stream",
            evidence_type=evidence_type,
            sha256=computed_sha256,
            trusted_reference=normalized_ref,
            status=status,
            investigator_id=investigator_id,
            uploaded_at=now_dt,
            last_verified_at=now_dt if status in ["VERIFIED", "MISMATCH"] else None
        )
        session.add(ev)
        session.commit()
        session.refresh(ev)

        # Audit event for ingestion
        log_audit_event(
            session=session,
            evidence_id=evidence_id,
            event_type="INGESTION",
            actor_id=investigator_id,
            details=f"Secure ingestion of forensic artifact '{clean_name}' ({file_size} bytes). Initial SHA-256 computed: {computed_sha256}",
            verification_result=None,
            commit=True
        )

        if normalized_ref:
            log_audit_event(
                session=session,
                evidence_id=evidence_id,
                event_type="REFERENCE_ADDED",
                actor_id=investigator_id,
                details=f"Trusted acquisition reference registered: {normalized_ref}",
                verification_result=None,
                commit=True
            )
            log_audit_event(
                session=session,
                evidence_id=evidence_id,
                event_type="INTEGRITY_VERIFICATION",
                actor_id=investigator_id,
                details=f"Initial integrity check: {'MATCH' if status == 'VERIFIED' else 'MISMATCH'}",
                verification_result=status,
                commit=True
            )

        return EvidenceItem.model_validate(ev)
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

def get_evidence_by_id(evidence_id: str, db: Optional[Session] = None) -> Optional[EvidenceItem]:
    session, owns_session = _resolve_session(db)
    try:
        ev = session.get(EvidenceModel, evidence_id)
        if not ev:
            return None
        return EvidenceItem.model_validate(ev)
    finally:
        if owns_session:
            session.close()

def list_evidence(case_id: Optional[str] = None, db: Optional[Session] = None) -> List[EvidenceItem]:
    session, owns_session = _resolve_session(db)
    try:
        stmt = select(EvidenceModel)
        if case_id:
            stmt = stmt.where(EvidenceModel.case_id == case_id)
        stmt = stmt.order_by(EvidenceModel.uploaded_at.desc())
        rows = session.execute(stmt).scalars().all()
        return [EvidenceItem.model_validate(r) for r in rows]
    finally:
        if owns_session:
            session.close()

def set_trusted_reference(
    evidence_id: str,
    reference_hash: str,
    actor_id: str = "Forensic_Investigator",
    db: Optional[Session] = None,
    storage_dir: Optional[Path] = None
) -> Tuple[Optional[EvidenceItem], VerificationResult]:
    clean_ref = reference_hash.strip().lower()
    if not HEX64_REGEX.match(clean_ref):
        raise ValueError("Invalid SHA-256 hash format. Must be 64 hexadecimal characters.")

    session, owns_session = _resolve_session(db)
    try:
        ev = session.get(EvidenceModel, evidence_id)
        if not ev:
            return None, None

        ev.trusted_reference = clean_ref
        session.commit()

        log_audit_event(
            session=session,
            evidence_id=evidence_id,
            event_type="REFERENCE_ADDED",
            actor_id=actor_id,
            details=f"Trusted reference hash updated to: {clean_ref}",
            verification_result=None,
            commit=True
        )

        verification = verify_evidence(
            evidence_id=evidence_id,
            actor_id=actor_id,
            db=session,
            storage_dir=storage_dir
        )
        session.refresh(ev)
        return EvidenceItem.model_validate(ev), verification
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

def verify_evidence(
    evidence_id: str,
    actor_id: str = "Forensic_Investigator",
    db: Optional[Session] = None,
    storage_dir: Optional[Path] = None
) -> VerificationResult:
    target_storage = storage_dir or config.STORAGE_DIR
    session, owns_session = _resolve_session(db)
    try:
        ev = session.get(EvidenceModel, evidence_id)
        if not ev:
            raise ValueError(f"Evidence record '{evidence_id}' not found.")

        storage_path = target_storage / ev.storage_filename
        now_dt = datetime.now(timezone.utc)
        trusted_ref = ev.trusted_reference
        filename = ev.filename

        if not storage_path.exists():
            new_status = "ERROR"
            message = "Forensic storage file missing or deleted on disk."
            match = False
            current_sha256 = None
        else:
            try:
                current_sha256 = calculate_file_sha256(storage_path)
                if not trusted_ref:
                    new_status = "UNVERIFIED"
                    match = False
                    message = "File hash computed from disk, but no trusted reference has been configured."
                elif current_sha256.lower() == trusted_ref.lower():
                    new_status = "VERIFIED"
                    match = True
                    message = "Cryptographic integrity verified: Disk SHA-256 matches trusted acquisition reference."
                else:
                    new_status = "MISMATCH"
                    match = False
                    message = f"INTEGRITY VIOLATION: Current file SHA-256 ({current_sha256}) differs from trusted reference ({trusted_ref})."
            except Exception as e:
                new_status = "ERROR"
                message = f"Disk I/O error during hash calculation: {str(e)}"
                match = False
                current_sha256 = None

        ev.status = new_status
        ev.last_verified_at = now_dt
        session.commit()

        log_audit_event(
            session=session,
            evidence_id=evidence_id,
            event_type="INTEGRITY_VERIFICATION",
            actor_id=actor_id,
            details=f"Integrity check performed. Computed: {current_sha256 or 'N/A'}. Reference: {trusted_ref or 'None'}. {message}",
            verification_result=new_status,
            commit=True
        )

        return VerificationResult(
            evidence_id=evidence_id,
            filename=filename,
            current_sha256=current_sha256,
            trusted_reference=trusted_ref,
            status=new_status,
            match=match,
            message=message,
            timestamp=now_dt.isoformat()
        )
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

def verify_all_evidence(
    case_id: Optional[str] = None,
    actor_id: str = "Forensic_Investigator",
    db: Optional[Session] = None,
    storage_dir: Optional[Path] = None
) -> List[VerificationResult]:
    session, owns_session = _resolve_session(db)
    try:
        stmt = select(EvidenceModel.id)
        if case_id:
            stmt = stmt.where(EvidenceModel.case_id == case_id)
        evidence_ids = session.execute(stmt).scalars().all()

        results = []
        for eid in evidence_ids:
            res = verify_evidence(
                evidence_id=eid,
                actor_id=actor_id,
                db=session,
                storage_dir=storage_dir
            )
            results.append(res)
        return results
    finally:
        if owns_session:
            session.close()

def get_audit_history(evidence_id: str, db: Optional[Session] = None) -> AuditHistoryResponse:
    session, owns_session = _resolve_session(db)
    try:
        ev = session.get(EvidenceModel, evidence_id)
        if not ev:
            return None

        stmt = (
            select(AuditLogModel)
            .where(AuditLogModel.evidence_id == evidence_id)
            .order_by(AuditLogModel.id.asc())
        )
        rows = session.execute(stmt).scalars().all()
        entries = [AuditLogEntry.model_validate(r) for r in rows]

        # Verify hash chain integrity
        chain_valid = True
        for entry in entries:
            ts_str = format_audit_timestamp(entry.timestamp)
            recomputed = compute_record_hash(
                event_id=entry.event_id,
                evidence_id=entry.evidence_id,
                event_type=entry.event_type,
                timestamp_str=ts_str,
                actor_id=entry.actor_id,
                details=entry.details,
                verification_result=entry.verification_result,
                previous_hash=entry.previous_hash
            )
            if recomputed != entry.record_hash:
                chain_valid = False
                break

        return AuditHistoryResponse(
            evidence_id=evidence_id,
            chain_valid=chain_valid,
            total_events=len(entries),
            history=entries
        )
    finally:
        if owns_session:
            session.close()
