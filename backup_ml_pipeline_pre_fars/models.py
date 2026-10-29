from pydantic import BaseModel, Field, field_validator, field_serializer, ConfigDict
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
import re

HEX64_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

# ====================================================================
# EVIDENCE & AUDIT CHAIN MODELS
# ====================================================================

class EvidenceItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    filename: str
    file_size: int
    mime_type: Optional[str] = None
    evidence_type: Optional[str] = None
    sha256: str
    trusted_reference: Optional[str] = None
    status: str
    investigator_id: Optional[str] = None
    uploaded_at: Union[str, datetime]
    last_verified_at: Optional[Union[str, datetime]] = None

    @field_serializer("uploaded_at")
    def serialize_uploaded_at(self, dt: Union[str, datetime]) -> str:
        return dt.isoformat() if isinstance(dt, datetime) else str(dt)

    @field_serializer("last_verified_at")
    def serialize_last_verified_at(self, dt: Optional[Union[str, datetime]]) -> Optional[str]:
        if dt is None:
            return None
        return dt.isoformat() if isinstance(dt, datetime) else str(dt)

class SetReferenceRequest(BaseModel):
    reference_hash: str = Field(..., description="64-character SHA-256 hexadecimal hash string")
    actor_id: Optional[str] = "Forensic_Investigator"

    @field_validator("reference_hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        clean = v.strip().lower()
        if not HEX64_REGEX.match(clean):
            raise ValueError("Reference hash must be a valid 64-character hexadecimal SHA-256 string")
        return clean

class VerifyRequest(BaseModel):
    actor_id: Optional[str] = "Forensic_Investigator"

class VerificationResult(BaseModel):
    evidence_id: str
    filename: str
    current_sha256: Optional[str] = None
    trusted_reference: Optional[str] = None
    status: str
    match: bool
    message: str
    timestamp: str

class AuditLogEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: str
    evidence_id: str
    event_type: str
    timestamp: Union[str, datetime]
    actor_id: str
    details: Optional[str] = None
    verification_result: Optional[str] = None
    previous_hash: str
    record_hash: str

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: Union[str, datetime]) -> str:
        return dt.isoformat() if isinstance(dt, datetime) else str(dt)

class AuditHistoryResponse(BaseModel):
    evidence_id: str
    chain_valid: bool
    total_events: int
    history: List[AuditLogEntry]

class HealthResponse(BaseModel):
    status: str
    backend: str
    storage_accessible: bool
    db_accessible: bool
    db_type: Optional[str] = None
    db_host: Optional[str] = None
    db_error: Optional[str] = None
    timestamp: str
    features: Optional[Dict[str, Any]] = None

# ====================================================================
# CASE & VEHICLE MODELS
# ====================================================================

class VehicleInfo(BaseModel):
    make: str
    model: str
    year: int
    vin: str
    ecu_firmware: Optional[str] = None
    edr_module: Optional[str] = None
    role: Optional[str] = "Subject Vehicle"
    color: Optional[str] = None

class LocationInfo(BaseModel):
    address: str
    lat: float
    lng: float
    speed_limit: float
    road_condition: str

class CaseItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    short_title: Optional[str] = None
    scenario_type: Optional[str] = None
    incident_time: Optional[str] = None
    location: Optional[LocationInfo] = None
    vehicle_info: Optional[VehicleInfo] = None
    summary: Optional[str] = None
    summary_tags: List[str] = []
    primary_data_sources: List[str] = []
    created_at: Optional[Union[str, datetime]] = None

# ====================================================================
# TIMELINE & 49 CFR PART 563 EDR TELEMETRY MODELS
# ====================================================================

class TimelineEventItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    time_offset_s: float
    event_name: str
    source: str
    description: Optional[str] = None
    speed_kph: Optional[float] = None
    brake_status: Optional[str] = None
    throttle_pct: Optional[float] = None
    steering_deg: Optional[float] = None
    delta_v_kph: Optional[float] = None
    is_critical: bool = False
    uncertainty_ms: int = 20

# ====================================================================
# EXPLAINABLE ANOMALIES & EVIDENCE CORRELATIONS
# ====================================================================

class AnomalyItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    time_rel: str
    component: str
    parameter: str
    observed_value: str
    baseline_threshold: str
    explanation: str
    supporting_evidence: Optional[str] = None
    confidence: float
    severity: str = "HIGH"
    limitations: Optional[str] = None

class CorrelationItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    primary_source: str
    secondary_source: str
    correlation_type: str
    confidence: float
    time_delta_ms: int
    finding: str
    status: str = "CORRELATED"

# ====================================================================
# MACHINE LEARNING (PYTORCH & SCIKIT-LEARN FARS PIPELINE)
# ====================================================================

class MLPredictionRequest(BaseModel):
    case_id: Optional[str] = None
    pre_impact_speed_kph: float = Field(..., ge=0, le=250, description="Vehicle speed 5s prior to impact (km/h)")
    delta_v_kph: float = Field(..., description="Estimated or EDR recorded crash velocity change (km/h)")
    brake_applied: bool = Field(True, description="Service brake switch transition recorded")
    seatbelt_latched: bool = Field(True, description="Restraint status per 49 CFR Part 563")
    collision_type: str = Field("ANGLE", description="FRONTAL, REAR, ANGLE, ROLLOVER, SIDESWIPE")
    road_condition: str = Field("DRY", description="DRY, WET, ICY, SNOW")
    airbag_deployed: bool = Field(True, description="Airbag squib deployment trigger")

class FeatureWeight(BaseModel):
    feature: str
    weight: float
    impact: str

class MLPredictionResponse(BaseModel):
    predicted_severity_class: str
    severity_risk_score: float
    collision_avoidability_probability: float
    confidence: float
    model_version: str
    framework: str
    pytorch_evaluation: Dict[str, Any]
    baseline_sklearn_comparison: Dict[str, Any]
    feature_contributions: List[FeatureWeight]
    disclaimer: str

class MLModelInfo(BaseModel):
    id: str
    name: str
    version: str
    framework: str
    task: str
    dataset_name: str
    accuracy: float
    f1_score: float
    loss: Optional[float] = None
    trained_at: Union[str, datetime]

# ====================================================================
# INCIDENT RECONSTRUCTION & WHAT-IF SIMULATION
# ====================================================================

class TrajectoryPoint(BaseModel):
    time_s: float
    x: float
    y: float
    speed_kph: float
    yaw_deg: float
    brake_pct: float
    steering_deg: float
    event_marker: Optional[str] = None

class ReconstructionDataResponse(BaseModel):
    case_id: str
    view_mode: str
    fps: int
    duration_s: float
    trajectory: List[TrajectoryPoint]
    assumptions: List[str]
    provenance: str
    regulatory_reference: str

class WhatIfSimulationRequest(BaseModel):
    case_id: str
    reaction_delay_ms: float = Field(0.0, description="Hypothetical driver reaction adjustment (ms)")
    latency_ms: float = Field(0.0, description="Vehicle network latency adjustment (ms)")
    speed_delta_kph: float = Field(0.0, description="Initial approach speed delta (km/h)")

class WhatIfSimulationResponse(BaseModel):
    case_id: str
    original_impact_speed_kph: float
    simulated_impact_speed_kph: float
    speed_reduction_kph: float
    avoidance_status: str
    stopping_distance_original_m: float
    stopping_distance_simulated_m: float
    distance_delta_m: float
    time_to_collision_margin_s: float
    physics_model_notes: str

# ====================================================================
# FORENSIC REPORT GENERATOR
# ====================================================================

class ForensicReportResponse(BaseModel):
    report_id: str
    report_number: str
    case_id: str
    title: str
    generated_at: str
    lead_investigator: str
    regulatory_reference: str
    case_overview: Dict[str, Any]
    vehicle_details: Dict[str, Any]
    evidence_inventory: List[Dict[str, Any]]
    chain_of_custody_summary: Dict[str, Any]
    timeline_49cfr563: List[Dict[str, Any]]
    anomalies_detected: List[Dict[str, Any]]
    evidence_correlations: List[Dict[str, Any]]
    ml_reconstruction_analysis: Dict[str, Any]
    what_if_kinematics: Dict[str, Any]
    investigative_conclusions: List[str]
    uncertainties_and_limitations: List[str]
