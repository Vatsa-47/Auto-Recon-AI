import json
import hashlib
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Generator, Tuple, List

logger = logging.getLogger("autorecon.database")

from sqlalchemy import (
    create_engine,
    Column,
    String,
    BigInteger,
    Integer,
    Float,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    select,
    text,
    Index,
    LargeBinary
)
from sqlalchemy.dialects.mysql import LONGBLOB
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    Session,
    relationship
)
from sqlalchemy.pool import StaticPool, QueuePool

from . import config

Base = declarative_base()

# ====================================================================
# ORM DATABASE ENTITIES
# ====================================================================

class CaseModel(Base):
    __tablename__ = "cases"

    id = Column(String(64), primary_key=True)
    title = Column(String(255), nullable=False)
    short_title = Column(String(255), nullable=True)
    scenario_type = Column(String(128), nullable=True)
    incident_time = Column(String(64), nullable=True)
    location_address = Column(String(255), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    speed_limit = Column(Float, nullable=True)
    road_condition = Column(String(128), nullable=True)
    summary = Column(Text, nullable=True)
    summary_tags = Column(Text, nullable=True)
    primary_data_sources = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    vehicles = relationship("VehicleModel", back_populates="case", cascade="all, delete-orphan")
    evidence_items = relationship("EvidenceModel", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEventModel", back_populates="case", cascade="all, delete-orphan", order_by="TimelineEventModel.time_offset_s.asc()")
    anomalies = relationship("AnomalyModel", back_populates="case", cascade="all, delete-orphan")
    correlations = relationship("CorrelationModel", back_populates="case", cascade="all, delete-orphan")

class VehicleModel(Base):
    __tablename__ = "vehicles"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    make = Column(String(64), nullable=False)
    model = Column(String(64), nullable=False)
    year = Column(Integer, nullable=False)
    vin = Column(String(64), nullable=False)
    ecu_firmware = Column(String(64), nullable=True)
    edr_module = Column(String(64), nullable=True)
    role = Column(String(64), default="Subject Vehicle")
    color = Column(String(32), nullable=True)

    case = relationship("CaseModel", back_populates="vehicles")

class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
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

    case = relationship("CaseModel", back_populates="evidence_items")
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

class TimelineEventModel(Base):
    __tablename__ = "timeline_events"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    time_offset_s = Column(Float, nullable=False, index=True)
    event_name = Column(String(128), nullable=False)
    source = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    speed_kph = Column(Float, nullable=True)
    brake_status = Column(String(32), nullable=True)
    throttle_pct = Column(Float, nullable=True)
    steering_deg = Column(Float, nullable=True)
    delta_v_kph = Column(Float, nullable=True)
    is_critical = Column(Boolean, default=False)
    uncertainty_ms = Column(Integer, default=20)

    case = relationship("CaseModel", back_populates="timeline_events")

class AnomalyModel(Base):
    __tablename__ = "anomalies"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    time_rel = Column(String(32), nullable=False)
    component = Column(String(128), nullable=False)
    parameter = Column(String(128), nullable=False)
    observed_value = Column(String(128), nullable=False)
    baseline_threshold = Column(String(128), nullable=False)
    explanation = Column(Text, nullable=False)
    supporting_evidence = Column(String(255), nullable=True)
    confidence = Column(Float, nullable=False)
    severity = Column(String(32), default="HIGH")
    limitations = Column(Text, nullable=True)

    case = relationship("CaseModel", back_populates="anomalies")

class CorrelationModel(Base):
    __tablename__ = "correlations"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    primary_source = Column(String(128), nullable=False)
    secondary_source = Column(String(128), nullable=False)
    correlation_type = Column(String(64), nullable=False)
    confidence = Column(Float, nullable=False)
    time_delta_ms = Column(Integer, nullable=False)
    finding = Column(Text, nullable=False)
    status = Column(String(32), default="CORRELATED")

    case = relationship("CaseModel", back_populates="correlations")

class MLModelRecord(Base):
    __tablename__ = "ml_models"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    version = Column(String(32), nullable=False)
    framework = Column(String(64), nullable=False)
    task = Column(String(128), nullable=False)
    dataset_name = Column(String(128), nullable=False)
    accuracy = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    loss = Column(Float, nullable=True)
    model_path = Column(String(255), nullable=True)
    trained_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    metadata_json = Column(Text, nullable=True)

class ForensicReportModel(Base):
    __tablename__ = "forensic_reports"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    report_number = Column(String(64), nullable=False, unique=True)
    title = Column(String(255), nullable=False)
    generated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    author_id = Column(String(128), nullable=False)
    regulatory_reference = Column(String(128), default="49 CFR Part 563 & ISO 26021")
    content_json = Column(Text, nullable=False)
    pdf_path = Column(String(512), nullable=True)
    sha256_hash = Column(String(64), nullable=True)

class FARSCrashRecord(Base):
    __tablename__ = "fars_crash_records"

    id = Column(String(64), primary_key=True)  # e.g. FARS-2024-10001
    st_case = Column(Integer, nullable=False, index=True)
    year = Column(Integer, nullable=False, default=2024)
    state_name = Column(String(64), nullable=False)
    city = Column(String(64), nullable=True)
    crash_date = Column(String(32), nullable=True)
    fatalities = Column(Integer, nullable=False, default=1)
    vehicles_count = Column(Integer, nullable=False, default=1)
    collision_type = Column(String(32), nullable=False)  # ANGLE, FRONTAL, REAR, ROLLOVER, SIDESWIPE
    weather = Column(String(32), nullable=False, default="CLEAR")
    light_condition = Column(String(32), nullable=False, default="DAYLIGHT")
    road_condition = Column(String(32), nullable=False, default="DRY")
    pre_speed_kph = Column(Float, nullable=False, default=65.0)
    delta_v_kph = Column(Float, nullable=False, default=25.0)
    rollover = Column(Boolean, default=False)
    event_sequence_json = Column(Text, nullable=True)
    vehicles_json = Column(Text, nullable=True)
    scene_config_json = Column(Text, nullable=True)
    sha256_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

class ReconstructionScenarioRecord(Base):
    __tablename__ = "reconstruction_scenarios"

    id = Column(String(64), primary_key=True)  # e.g. SCENARIO-FARS-2024-10001
    case_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    source_type = Column(String(32), default="FARS_HISTORICAL")  # FARS_HISTORICAL or FORENSIC_TELEMETRY
    provenance_json = Column(Text, nullable=False)
    assumptions_json = Column(Text, nullable=True)
    actors_json = Column(Text, nullable=False)
    trajectories_json = Column(Text, nullable=False)
    scene_config_json = Column(Text, nullable=False)
    ml_prediction_json = Column(Text, nullable=True)
    sha256_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

class UploadedDatasetModel(Base):
    __tablename__ = "uploaded_datasets"

    id = Column(String(64), primary_key=True)
    original_filename = Column(String(255), nullable=False)
    file_format = Column(String(32), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    file_data = Column(LargeBinary().with_variant(LONGBLOB, "mysql"), nullable=False)
    upload_timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    processing_status = Column(String(64), nullable=False, default="UPLOADED")
    scenario_id = Column(String(64), nullable=True)

class DatasetModel(Base):
    __tablename__ = "datasets"

    id = Column(String(64), primary_key=True)  # e.g. DS-20241024-xxxx
    filename = Column(String(255), nullable=False)
    stored_path = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    file_size_bytes = Column(BigInteger, nullable=False)
    file_format = Column(String(32), nullable=False)  # CSV, JSON
    dataset_type = Column(String(64), nullable=False, default="TELEMETRY_TIMESERIES")  # TELEMETRY_TIMESERIES, HISTORICAL_FARS, GENERAL_TABULAR
    row_count = Column(Integer, nullable=False, default=0)
    col_count = Column(Integer, nullable=False, default=0)
    schema_json = Column(Text, nullable=True)
    mapping_json = Column(Text, nullable=True)
    processing_status = Column(String(32), nullable=False, default="UPLOADED")  # UPLOADED, VALIDATED, PROCESSED, ERROR
    case_id = Column(String(64), nullable=True, index=True)
    uploaded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    processed_at = Column(DateTime, nullable=True)

class DatasetAnalysisModel(Base):
    __tablename__ = "dataset_analyses"

    id = Column(String(64), primary_key=True)  # e.g. ANL-xxxx
    dataset_id = Column(String(64), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(String(64), nullable=True, index=True)
    model_version = Column(String(64), nullable=False, default="3.0.0-PyTorch+FARS2024")
    ml_severity_json = Column(Text, nullable=True)
    ml_pattern_json = Column(Text, nullable=True)
    similar_cases_json = Column(Text, nullable=True)
    scenario_id = Column(String(64), nullable=True)
    assumptions_json = Column(Text, nullable=True)
    graphs_metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

# ====================================================================
# ENGINE & SESSION MANAGEMENT
# ====================================================================

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
        # Authoritative MySQL Engine
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
    """FastAPI dependency that yields an active database session and guarantees closure."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()

def check_db_connection(engine=None) -> Tuple[bool, Optional[str]]:
    """Strictly tests active MySQL connection with a real query."""
    target_engine = engine or get_engine()
    try:
        with target_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except Exception as e:
        return False, str(e)

def init_db(engine=None):
    """Safely initializes all tables in MySQL and executes non-destructive schema migrations."""
    target_engine = engine or get_engine()
    Base.metadata.create_all(bind=target_engine)
    
    # Non-destructive migration for forensic_reports columns if table already existed (MySQL only)
    if target_engine.dialect.name == "mysql":
        try:
            with target_engine.connect() as conn:
                res = conn.execute(text("SHOW COLUMNS FROM forensic_reports LIKE 'pdf_path'")).fetchone()
                if not res:
                    conn.execute(text("ALTER TABLE forensic_reports ADD COLUMN pdf_path VARCHAR(512) NULL"))
                res2 = conn.execute(text("SHOW COLUMNS FROM forensic_reports LIKE 'sha256_hash'")).fetchone()
                if not res2:
                    conn.execute(text("ALTER TABLE forensic_reports ADD COLUMN sha256_hash VARCHAR(64) NULL"))
                conn.commit()
        except Exception as e:
            logger.warning(f"Schema column check/migration on forensic_reports: {e}")

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

# ====================================================================
# SEED SAMPLE FORENSIC CASES & EVIDENCE
# ====================================================================

def seed_sample_evidence_if_empty(session: Optional[Session] = None, storage_dir: Optional[Path] = None):
    """Seed comprehensive forensic cases, vehicles, telemetry, and evidence if empty."""
    target_storage = storage_dir or config.STORAGE_DIR
    target_storage.mkdir(parents=True, exist_ok=True)

    owns_session = False
    if session is None:
        factory = get_session_factory()
        session = factory()
        owns_session = True

    try:
        # 1. Ensure Demonstration Cases exist
        case_count = session.query(CaseModel).count()
        if case_count == 0:
            cases_data = [
                {
                    "id": "CASE_AF_8902",
                    "title": "Urban Intersection — Brake Response Anomaly",
                    "short_title": "1. Urban Intersection — Brake Response Anomaly",
                    "scenario_type": "Intersection Collision (Timing Anomaly Investigation)",
                    "incident_time": "2026-08-14 17:42:19 UTC",
                    "location_address": "Intersection of Cyber Highway & 4th Avenue",
                    "latitude": 28.613939,
                    "longitude": 77.209021,
                    "speed_limit": 60.0,
                    "road_condition": "Dry Asphalt, Daylight",
                    "summary": "Vehicle collided with cross-traffic at 57.8 km/h. Physical driver brake pedal activation was confirmed at t = -3.10s, but hydraulic brake line pressure was delayed by 2.1 seconds on the vehicle network.",
                    "summary_tags": json.dumps(["Brake Delay Anomaly", "Driver Input Recorded", "Impact Deceleration Recorded", "Demonstration Case"]),
                    "primary_data_sources": json.dumps(["CAN Bus Log", "EDR EEPROM", "Brake Transducers", "Video Flow"]),
                    "vehicle": {
                        "id": "VEH_8902_01",
                        "make": "Apex EV",
                        "model": "Vortex Sedan",
                        "year": 2025,
                        "vin": "1HGCR2F83PA098124",
                        "ecu_firmware": "v4.12.8-prod",
                        "edr_module": "Bosch CDR Gen 4",
                        "role": "Subject Vehicle",
                        "color": "Obsidian Blue"
                    },
                    "timeline": [
                        {"id": "TL_8902_01", "time_offset_s": -5.0, "event_name": "Steady Approach", "source": "CAN (0x0284)", "speed_kph": 62.4, "brake_status": "OFF", "throttle_pct": 28.0, "steering_deg": -0.8, "delta_v_kph": 0.0, "is_critical": False},
                        {"id": "TL_8902_02", "time_offset_s": -3.1, "event_name": "Driver Brake Depressed", "source": "EDR Pin 14", "speed_kph": 60.1, "brake_status": "ON", "throttle_pct": 0.0, "steering_deg": -1.2, "delta_v_kph": -0.5, "is_critical": True},
                        {"id": "TL_8902_03", "time_offset_s": -2.5, "event_name": "CAN Bus Load Saturation", "source": "CAN Monitor", "speed_kph": 59.8, "brake_status": "ON", "throttle_pct": 0.0, "steering_deg": -1.5, "delta_v_kph": -0.8, "is_critical": True},
                        {"id": "TL_8902_04", "time_offset_s": -1.0, "event_name": "Hydraulic Brake Pressure Rise", "source": "CAN (0x01B0)", "speed_kph": 58.9, "brake_status": "ON", "throttle_pct": 0.0, "steering_deg": -2.0, "delta_v_kph": -2.1, "is_critical": True},
                        {"id": "TL_8902_05", "time_offset_s": 0.0, "event_name": "Cross-Traffic Impact", "source": "EDR Pulse", "speed_kph": 57.8, "brake_status": "ON", "throttle_pct": 0.0, "steering_deg": -4.5, "delta_v_kph": -24.8, "is_critical": True}
                    ],
                    "anomalies": [
                        {"id": "AN_8902_01", "time_rel": "t = -3.10s", "component": "CAN Bus Arbitration", "parameter": "Bus Utilization", "observed_value": "94%", "baseline_threshold": "< 60%", "explanation": "CAN bus load spiked to 94% with repetitive high-priority frames (ID 0x0284), causing queue delay for hydraulic brake line actuation.", "supporting_evidence": "can_bus_traffic_intersection_AF01.log", "confidence": 0.94, "severity": "HIGH"},
                        {"id": "AN_8902_02", "time_rel": "t = -1.00s", "component": "Brake Actuator ECU", "parameter": "Transmission Latency", "observed_value": "2100 ms", "baseline_threshold": "< 100 ms", "explanation": "Hydraulic pressure command (0x01B0) lagged physical pedal depression by 2.1 seconds.", "supporting_evidence": "edr_event_record_AF01.bin", "confidence": 0.92, "severity": "CRITICAL"}
                    ],
                    "correlations": [
                        {"id": "CORR_8902_01", "primary_source": "EDR Brake Switch (Pin 14)", "secondary_source": "CAN ID 0x01B0", "correlation_type": "Temporal Response Discrepancy", "confidence": 0.96, "time_delta_ms": 2100, "finding": "Pedal depressed at t=-3.10s, hydraulic command issued at t=-1.00s. Unambiguous 2100ms actuation delay confirmed."}
                    ]
                },
                {
                    "id": "CASE_AF_4421",
                    "title": "Highway Merge — Sensor Blindspot Mismatch",
                    "short_title": "2. Highway Merge — Sensor Blindspot Mismatch",
                    "scenario_type": "Side Collision (Sensor Fusion Inconsistency)",
                    "incident_time": "2026-07-29 08:15:44 UTC",
                    "location_address": "Interstate 80 Eastbound, Milepost 42",
                    "latitude": 40.712776,
                    "longitude": -74.005974,
                    "speed_limit": 105.0,
                    "road_condition": "Wet Surface, Heavy Spray",
                    "summary": "Vehicle initiated lane change at 98 km/h. Radar sensor detected overtaking vehicle 35m behind, while lateral ultrasonic sensors reported clear flank.",
                    "summary_tags": json.dumps(["Sensor Fusion Mismatch", "Blindspot Collision", "Wet Road", "ADAS Telemetry"]),
                    "primary_data_sources": json.dumps(["Radar Point Cloud", "Ultrasonic Bus", "Camera Lane Detect", "IMU"]),
                    "vehicle": {
                        "id": "VEH_4421_01",
                        "make": "Zenith Motors",
                        "model": "Krypton SUV",
                        "year": 2024,
                        "vin": "4T1B11HK5PU784129",
                        "ecu_firmware": "v3.8.1-rel",
                        "edr_module": "Denso ADR-3",
                        "role": "Subject Vehicle",
                        "color": "Silver Metallic"
                    },
                    "timeline": [
                        {"id": "TL_4421_01", "time_offset_s": -4.0, "event_name": "Turn Signal Left ON", "source": "CAN (0x0188)", "speed_kph": 98.2, "brake_status": "OFF", "throttle_pct": 32.0, "steering_deg": 4.2, "delta_v_kph": 0.0, "is_critical": False},
                        {"id": "TL_4421_02", "time_offset_s": -2.2, "event_name": "Radar Object Acquired", "source": "Radar ECU", "speed_kph": 98.0, "brake_status": "OFF", "throttle_pct": 30.0, "steering_deg": 8.5, "delta_v_kph": -0.2, "is_critical": True},
                        {"id": "TL_4421_03", "time_offset_s": 0.0, "event_name": "Lateral Sideswipe Impact", "source": "EDR Lateral Accel", "speed_kph": 94.6, "brake_status": "OFF", "throttle_pct": 18.0, "steering_deg": -14.2, "delta_v_kph": -12.4, "is_critical": True}
                    ],
                    "anomalies": [
                        {"id": "AN_4421_01", "time_rel": "t = -2.20s", "component": "Sensor Fusion Filter", "parameter": "Target Tracking Confidence", "observed_value": "0.41", "baseline_threshold": "> 0.80", "explanation": "Radar detected closing target at relative -12 m/s, but ultrasonic flank sensor masked echo due to road spray.", "supporting_evidence": "radar_point_cloud_highway_AF02.dat", "confidence": 0.89, "severity": "HIGH"}
                    ],
                    "correlations": [
                        {"id": "CORR_4421_01", "primary_source": "Radar Range Rate", "secondary_source": "Ultrasonic Flank Transducer", "correlation_type": "Sensor Disagreement", "confidence": 0.91, "time_delta_ms": 150, "finding": "Radar tracked target at 35m range; ultrasonic failed to trigger warning prior to lateral engagement."}
                    ]
                },
                {
                    "id": "CASE_AF_6715",
                    "title": "Curved Descent — ESP Yaw Stability Loss",
                    "short_title": "3. Curved Descent — ESP Yaw Stability Loss",
                    "scenario_type": "Loss of Control / Rollover Investigation",
                    "incident_time": "2026-06-11 22:04:12 UTC",
                    "location_address": "Mountain Route 9, Hairpin Bend 14",
                    "latitude": 39.739236,
                    "longitude": -104.990251,
                    "speed_limit": 45.0,
                    "road_condition": "Damp Asphalt, Sub-Zero",
                    "summary": "Vehicle entered descending curve at 68 km/h (speed limit 45 km/h). Telemetry displays yaw-rate deviation exceeding linear steering limits followed by asymmetric wheel spin.",
                    "summary_tags": json.dumps(["ESP Intervention", "Oversteer Yaw Discrepancy", "Mountain Route", "EDR Pre-Crash"]),
                    "primary_data_sources": json.dumps(["Wheel Speed Sensors", "IMU Gyroscope", "ESP Modulator", "Steering Angle"]),
                    "vehicle": {
                        "id": "VEH_6715_01",
                        "make": "AeroTech",
                        "model": "Pulse GT",
                        "year": 2026,
                        "vin": "WAUZZZ8V7FA102934",
                        "ecu_firmware": "v5.0.2-sport",
                        "edr_module": "Continental Safety Gateway",
                        "role": "Subject Vehicle",
                        "color": "Racing Red"
                    },
                    "timeline": [
                        {"id": "TL_6715_01", "time_offset_s": -3.5, "event_name": "Curve Entry Overspeed", "source": "CAN (0x02B0)", "speed_kph": 68.4, "brake_status": "OFF", "throttle_pct": 15.0, "steering_deg": -32.0, "delta_v_kph": 0.0, "is_critical": False},
                        {"id": "TL_6715_02", "time_offset_s": -1.8, "event_name": "Yaw Rate Exceeds Model", "source": "IMU Gyro", "speed_kph": 64.2, "brake_status": "ON", "throttle_pct": 0.0, "steering_deg": -45.0, "delta_v_kph": -1.8, "is_critical": True},
                        {"id": "TL_6715_03", "time_offset_s": 0.0, "event_name": "Guardrail Strike", "source": "EDR Impact Pulse", "speed_kph": 52.1, "brake_status": "ON", "throttle_pct": 0.0, "steering_deg": 18.0, "delta_v_kph": -19.6, "is_critical": True}
                    ],
                    "anomalies": [
                        {"id": "AN_6715_01", "time_rel": "t = -1.80s", "component": "ESP Stability Unit", "parameter": "Yaw Rate Error", "observed_value": "18.4 deg/s", "baseline_threshold": "< 4.0 deg/s", "explanation": "Vehicle body rotated at 18.4 deg/s counter to steering angle command, indicating severe oversteer spin.", "supporting_evidence": "edr_event_record_AF01.bin", "confidence": 0.95, "severity": "CRITICAL"}
                    ],
                    "correlations": [
                        {"id": "CORR_6715_01", "primary_source": "Steering Angle Sensor", "secondary_source": "Yaw Rate Gyroscope", "correlation_type": "Kinematic Model Deviation", "confidence": 0.97, "time_delta_ms": 40, "finding": "Incompatible steering-to-yaw trajectory confirming traction detachment on damp mountain curve."}
                    ]
                }
            ]

            for cdata in cases_data:
                vehicle_data = cdata.pop("vehicle")
                timeline_data = cdata.pop("timeline")
                anomalies_data = cdata.pop("anomalies")
                correlations_data = cdata.pop("correlations")

                case_obj = CaseModel(**cdata)
                session.add(case_obj)
                session.flush()

                v_obj = VehicleModel(case_id=case_obj.id, **vehicle_data)
                session.add(v_obj)

                for titem in timeline_data:
                    t_obj = TimelineEventModel(case_id=case_obj.id, **titem)
                    session.add(t_obj)

                for aitem in anomalies_data:
                    a_obj = AnomalyModel(case_id=case_obj.id, **aitem)
                    session.add(a_obj)

                for corr_item in correlations_data:
                    c_obj = CorrelationModel(case_id=case_obj.id, **corr_item)
                    session.add(c_obj)

            session.commit()

        # 2. Ensure Demonstration Evidence Items exist
        evidence_count = session.query(EvidenceModel).count()
        if evidence_count == 0:
            sample_items = [
                {
                    "id": "ev-can-urban-01",
                    "case_id": "CASE_AF_8902",
                    "filename": "can_bus_traffic_intersection_AF01.log",
                    "content": b"TIMESTAMP,ID,DATA\n1710921000.100,0x0284,B1 2A 00 00\n1710921000.120,0x0312,01 FF 4C 88\n1710921001.000,0x01B0,BRAKE_CMD_APPLIED\n",
                    "evidence_type": "CAN_BUS_DUMP",
                    "investigator_id": "Forensic_Lead_Det_Smith",
                    "trusted_match": True
                },
                {
                    "id": "ev-edr-urban-01",
                    "case_id": "CASE_AF_8902",
                    "filename": "edr_event_record_AF01.bin",
                    "content": b"EDR_CRASH_DATA_BLOCK_HEADER_REV3.2_AF01_DELTA_V_-24.8KPH_SEATBELT_LATCHED",
                    "evidence_type": "EDR_BINARY",
                    "investigator_id": "Forensic_Lead_Det_Smith",
                    "trusted_match": True
                },
                {
                    "id": "ev-dashcam-urban-01",
                    "case_id": "CASE_AF_8902",
                    "filename": "front_dashcam_telemetry_AF01.mp4.meta",
                    "content": b"DASHCAM_METADATA_GPS_LAT_37.7749_LON_-122.4194_FRAME_RATE_60FPS_LENS_FRONT",
                    "evidence_type": "DASHCAM_VIDEO",
                    "investigator_id": "Forensic_Lead_Det_Smith",
                    "trusted_match": False,
                },
                {
                    "id": "ev-radar-highway-02",
                    "case_id": "CASE_AF_4421",
                    "filename": "radar_point_cloud_highway_AF02.dat",
                    "content": b"RADAR_FRAME_AF02_RANGE_45M_VELOCITY_REL_-12MS_TARGET_REAR_VEHICLE",
                    "evidence_type": "RADAR_POINTCLOUD",
                    "investigator_id": "Officer_Rodriguez",
                    "trusted_match": True
                },
                {
                    "id": "ev-can-overtake-03",
                    "case_id": "CASE_AF_6715",
                    "filename": "can_bus_blindspot_AF03.log",
                    "content": b"CAN_AF03_LANE_CHANGE_INDICATOR_LEFT_BLIND_SPOT_WARN_HIGH",
                    "evidence_type": "CAN_BUS_DUMP",
                    "investigator_id": "Investigator_Chen",
                    "trusted_match": True
                }
            ]

            now_dt = datetime.now(timezone.utc)
            for item in sample_items:
                storage_filename = f"{item['id']}_{item['filename']}"
                file_path = target_storage / storage_filename
                if not file_path.exists():
                    file_path.write_bytes(item["content"])

                computed_hash = hashlib.sha256(item["content"]).hexdigest().lower()
                trusted_ref = computed_hash if item["trusted_match"] else None
                status = "VERIFIED" if item["trusted_match"] else "UNVERIFIED"

                ev_record = EvidenceModel(
                    id=item["id"],
                    case_id=item["case_id"],
                    filename=item["filename"],
                    storage_filename=storage_filename,
                    file_size=len(item["content"]),
                    mime_type="application/octet-stream",
                    evidence_type=item["evidence_type"],
                    sha256=computed_hash,
                    trusted_reference=trusted_ref,
                    status=status,
                    investigator_id=item["investigator_id"],
                    uploaded_at=now_dt,
                    last_verified_at=now_dt if status == "VERIFIED" else None
                )
                session.add(ev_record)
                session.flush()

                # Genesis ingestion event
                log_audit_event(
                    session=session,
                    evidence_id=ev_record.id,
                    event_type="EVIDENCE_INGESTED",
                    actor_id=item["investigator_id"],
                    details=f"Acquired forensic artifact {item['filename']} (Size: {len(item['content'])} bytes)",
                    verification_result=status,
                    commit=False
                )

                if trusted_ref:
                    log_audit_event(
                        session=session,
                        evidence_id=ev_record.id,
                        event_type="REFERENCE_HASH_REGISTERED",
                        actor_id="Evidence_Custodian",
                        details=f"Trusted acquisition hash bound: {trusted_ref}",
                        verification_result="VERIFIED",
                        commit=False
                    )

            session.commit()

        # 3. Ensure ML Model Records exist
        ml_count = session.query(MLModelRecord).count()
        if ml_count == 0:
            pt_rec = MLModelRecord(
                id="ML_PYTORCH_SEVERITY_V2",
                name="PyTorch Crash Severity Neural Network",
                version="2.0.0",
                framework="PyTorch 2.x",
                task="KABCO Crash Injury Severity Estimation",
                dataset_name="NHTSA FARS 2024 National Census",
                accuracy=0.884,
                f1_score=0.871,
                loss=0.312,
                model_path=str(config.ML_MODELS_DIR / "crash_severity_pytorch.pt"),
                metadata_json=json.dumps({"input_dim": 20, "num_classes": 4, "framework": "PyTorch"})
            )
            sk_rec = MLModelRecord(
                id="ML_SKLEARN_BASELINE_V1",
                name="Random Forest Baseline Classifier",
                version="2.0.0",
                framework="Scikit-learn",
                task="KABCO Baseline Comparison",
                dataset_name="NHTSA FARS 2024 National Census",
                accuracy=0.862,
                f1_score=0.849,
                loss=None,
                model_path=str(config.ML_MODELS_DIR / "baseline_sklearn.joblib"),
                metadata_json=json.dumps({"framework": "Scikit-learn"})
            )
            session.add(pt_rec)
            session.add(sk_rec)
            session.commit()

    finally:
        if owns_session:
            session.close()
