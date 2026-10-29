import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Generator, Tuple

from sqlalchemy import (
    create_engine,
    Column,
    String,
    BigInteger,
    Integer,
    Text,
    DateTime,
    ForeignKey,
    select,
    text,
    Index
)
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    Session,
    relationship
)
from sqlalchemy.pool import StaticPool, QueuePool

from . import config

Base = declarative_base()

class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    storage_filename = Column(String(255), nullable=False, unique=True)
    file_size = Column(BigInteger, nullable=False)
    mime_type = Column(String(128), nullable=True)
    evidence_type = Column(String(64), nullable=True)
    sha256 = Column(String(64), nullable=False, index=True)
    trusted_reference = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False)
    investigator_id = Column(String(128), nullable=True)
    uploaded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    last_verified_at = Column(DateTime, nullable=True)

    audit_events = relationship("AuditLogModel", back_populates="evidence", cascade="all, delete-orphan", order_by="AuditLogModel.id.asc()")

class AuditLogModel(Base):
    __tablename__ = "audit_log"

    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    event_id = Column(String(64), nullable=False, unique=True, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    actor_id = Column(String(128), nullable=False)
    details = Column(Text, nullable=True)
    verification_result = Column(String(32), nullable=True)
    previous_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)

    evidence = relationship("EvidenceModel", back_populates="audit_events")

__table_args__ = (
    Index("idx_audit_evidence_time", AuditLogModel.evidence_id, AuditLogModel.timestamp),
)

# Engine & Session Factory Cache
_engine = None
_SessionFactory = None

def create_db_engine(url: Optional[str] = None):
    target_url = url or config.DATABASE_URL
    if target_url.startswith("sqlite"):
        engine = create_engine(
            target_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )
    else:
        # MySQL engine with connection pool and automatic reconnect ping
        engine = create_engine(
            target_url,
            poolclass=QueuePool,
            pool_size=config.DB_POOL_SIZE,
            max_overflow=config.DB_MAX_OVERFLOW,
            pool_recycle=config.DB_POOL_RECYCLE,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 5}
        )
    return engine

def get_engine():
    global _engine
    if _engine is None:
        _engine = create_db_engine()
    return _engine

def set_engine(engine):
    global _engine, _SessionFactory
    _engine = engine
    _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionFactory

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session and guarantees closure."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()

def check_db_connection(engine=None) -> Tuple[bool, Optional[str]]:
    """Test connection to the database. Returns (is_healthy, error_detail)."""
    target_engine = engine or get_engine()
    try:
        with target_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except Exception as e:
        return False, str(e)

def init_db(engine=None):
    """Create all tables in the configured database."""
    target_engine = engine or get_engine()
    Base.metadata.create_all(bind=target_engine)

def format_audit_timestamp(ts: Any) -> str:
    if isinstance(ts, str):
        if "+" in ts or ts.endswith("Z"):
            return ts
        clean = ts.replace(" ", "T")
        return f"{clean}+00:00"
    elif isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.isoformat()
    return str(ts)

def compute_record_hash(
    event_id: str,
    evidence_id: str,
    event_type: str,
    timestamp_str: str,
    actor_id: str,
    details: Optional[str],
    verification_result: Optional[str],
    previous_hash: str
) -> str:
    content = f"{event_id}|{evidence_id}|{event_type}|{timestamp_str}|{actor_id}|{details or ''}|{verification_result or ''}|{previous_hash}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def get_latest_audit_hash(session: Session, evidence_id: Optional[str] = None) -> str:
    if evidence_id:
        stmt = (
            select(AuditLogModel.record_hash)
            .where(AuditLogModel.evidence_id == evidence_id)
            .order_by(AuditLogModel.id.desc())
            .limit(1)
        )
    else:
        stmt = (
            select(AuditLogModel.record_hash)
            .order_by(AuditLogModel.id.desc())
            .limit(1)
        )
    res = session.execute(stmt).scalar_one_or_none()
    return res if res else "0" * 64

def log_audit_event(
    session: Session,
    evidence_id: str,
    event_type: str,
    actor_id: str,
    details: Optional[str] = None,
    verification_result: Optional[str] = None,
    commit: bool = True
) -> AuditLogModel:
    event_id = str(uuid.uuid4())
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    previous_hash = get_latest_audit_hash(session, evidence_id)
    record_hash = compute_record_hash(
        event_id=event_id,
        evidence_id=evidence_id,
        event_type=event_type,
        timestamp_str=now_iso,
        actor_id=actor_id,
        details=details,
        verification_result=verification_result,
        previous_hash=previous_hash
    )

    entry = AuditLogModel(
        event_id=event_id,
        evidence_id=evidence_id,
        event_type=event_type,
        timestamp=now_dt,
        actor_id=actor_id,
        details=details,
        verification_result=verification_result,
        previous_hash=previous_hash,
        record_hash=record_hash
    )
    session.add(entry)
    if commit:
        session.commit()
        session.refresh(entry)
    return entry

def seed_sample_evidence_if_empty(session: Optional[Session] = None, storage_dir: Optional[Path] = None):
    """Seed initial demonstration evidence if database table is empty."""
    target_storage = storage_dir or config.STORAGE_DIR
    target_storage.mkdir(parents=True, exist_ok=True)

    owns_session = False
    if session is None:
        factory = get_session_factory()
        session = factory()
        owns_session = True

    try:
        count = session.query(EvidenceModel).count()
        if count > 0:
            return

        sample_items = [
            {
                "id": "ev-can-urban-01",
                "case_id": "CASE_AF_01",
                "filename": "can_bus_traffic_intersection_AF01.log",
                "content": b"TIMESTAMP,ID,DATA\n1710921000.100,0x0284,B1 2A 00 00\n1710921000.120,0x0312,01 FF 4C 88\n1710921001.000,0x01A0,BRAKE_CMD_APPLIED\n",
                "evidence_type": "CAN_BUS_DUMP",
                "investigator_id": "Forensic_Lead_Det_Smith",
                "trusted_match": True
            },
            {
                "id": "ev-edr-urban-01",
                "case_id": "CASE_AF_01",
                "filename": "edr_event_record_AF01.bin",
                "content": b"EDR_CRASH_DATA_BLOCK_HEADER_REV3.2_AF01_DELTA_V_-24.8KPH_SEATBELT_LATCHED",
                "evidence_type": "EDR_BINARY",
                "investigator_id": "Forensic_Lead_Det_Smith",
                "trusted_match": True
            },
            {
                "id": "ev-dashcam-urban-01",
                "case_id": "CASE_AF_01",
                "filename": "front_dashcam_telemetry_AF01.mp4.meta",
                "content": b"DASHCAM_METADATA_GPS_LAT_37.7749_LON_-122.4194_FRAME_RATE_60FPS_LENS_FRONT",
                "evidence_type": "DASHCAM_VIDEO",
                "investigator_id": "Forensic_Lead_Det_Smith",
                "trusted_match": False,
            },
            {
                "id": "ev-radar-highway-02",
                "case_id": "CASE_AF_02",
                "filename": "radar_point_cloud_highway_AF02.dat",
                "content": b"RADAR_FRAME_AF02_RANGE_45M_VELOCITY_REL_-12MS_TARGET_REAR_VEHICLE",
                "evidence_type": "RADAR_POINTCLOUD",
                "investigator_id": "Officer_Rodriguez",
                "trusted_match": True
            },
            {
                "id": "ev-can-overtake-03",
                "case_id": "CASE_AF_03",
                "filename": "can_bus_blindspot_AF03.log",
                "content": b"CAN_AF03_LANE_CHANGE_INDICATOR_LEFT_BLIND_SPOT_WARN_HIGH",
                "evidence_type": "CAN_BUS_DUMP",
                "investigator_id": "Investigator_Chen",
                "trusted_match": True
            }
        ]

        now_dt = datetime.now(timezone.utc)
        for item in sample_items:
            data = item["content"]
            file_hash = hashlib.sha256(data).hexdigest()
            storage_name = f"{item['id']}_{item['filename']}"
            file_path = target_storage / storage_name
            with open(file_path, "wb") as f:
                f.write(data)

            if item["trusted_match"]:
                trusted_ref = file_hash
                status = "VERIFIED"
            else:
                trusted_ref = None
                status = "UNVERIFIED"

            ev = EvidenceModel(
                id=item["id"],
                case_id=item["case_id"],
                filename=item["filename"],
                storage_filename=storage_name,
                file_size=len(data),
                mime_type="application/octet-stream",
                evidence_type=item["evidence_type"],
                sha256=file_hash,
                trusted_reference=trusted_ref,
                status=status,
                investigator_id=item["investigator_id"],
                uploaded_at=now_dt,
                last_verified_at=now_dt if status == "VERIFIED" else None
            )
            session.add(ev)
            session.commit()

            # Audit entries
            log_audit_event(
                session=session,
                evidence_id=item["id"],
                event_type="INGESTION",
                actor_id=item["investigator_id"],
                details=f"Secure ingestion of sample artifact {item['filename']} (Size: {len(data)} bytes). Initial SHA-256 computed.",
                verification_result=None,
                commit=True
            )

            if trusted_ref:
                log_audit_event(
                    session=session,
                    evidence_id=item["id"],
                    event_type="REFERENCE_ADDED",
                    actor_id=item["investigator_id"],
                    details="Trusted acquisition reference registered from verified field property sheet.",
                    verification_result=None,
                    commit=True
                )
                log_audit_event(
                    session=session,
                    evidence_id=item["id"],
                    event_type="INTEGRITY_VERIFICATION",
                    actor_id="System_Automated_Verifier",
                    details="Baseline disk integrity check: Computed hash matches trusted reference exactly.",
                    verification_result="VERIFIED",
                    commit=True
                )
    finally:
        if owns_session:
            session.close()
