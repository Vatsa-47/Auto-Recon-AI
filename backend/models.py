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
    vehicle_weight_class: str = Field("SEDAN", description="SEDAN, SUV, PICKUP, COMPACT")

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

class MLPatternRequest(BaseModel):
    pre_impact_speed_kph: float = Field(..., ge=0, le=250)
    delta_v_kph: float = Field(...)
    brake_applied: bool = Field(True)
    seatbelt_latched: bool = Field(True)
    airbag_deployed: bool = Field(True)
    road_condition: str = Field("DRY")
    vehicle_weight_class: str = Field("SEDAN")

class MLPatternResponse(BaseModel):
    predicted_pattern: str
    confidence: float
    pattern_probabilities: Dict[str, float]
    model_framework: str
    dataset_provenance: str

class MLSimilarityRequest(BaseModel):
    pre_impact_speed_kph: float = Field(..., ge=0, le=250)
    delta_v_kph: float = Field(...)
    collision_type: str = Field("ANGLE")
    road_condition: str = Field("DRY")
    vehicle_weight_class: str = Field("SEDAN")
    seatbelt_latched: bool = Field(True)
    airbag_deployed: bool = Field(True)
    top_k: int = Field(5, ge=1, le=20)

class SimilarCrashItem(BaseModel):
    rank: int
    dataset_index: int
    similarity_score: float
    collision_type: str
    pre_impact_speed_kph: float
    delta_v_kph: float
    road_condition: str
    vehicle_weight_class: str
    injury_severity_outcome: str
    comparable_factors: List[str]

class MLSimilarityResponse(BaseModel):
    query_summary: Dict[str, Any]
    matched_crashes: List[SimilarCrashItem]
    dataset_provenance: str

class FARSCaseSummary(BaseModel):
    id: str
    st_case: int
    year: int
    state: str
    city: Optional[str] = None
    fatalities: int
    vehicles_count: int
    collision_type: str
    weather: str
    light_condition: str
    pre_speed_kph: float
    delta_v_kph: float
    rollover: bool
    sha256_hash: str

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
    case_overview: Dict[str, Any] = {}
    vehicle_details: Dict[str, Any] = {}
    evidence_inventory: List[Dict[str, Any]] = []
    chain_of_custody_summary: Dict[str, Any] = {}
    timeline_49cfr563: List[Dict[str, Any]] = []
    anomalies_detected: List[Dict[str, Any]] = []
    evidence_correlations: List[Dict[str, Any]] = []
    ml_reconstruction_analysis: Dict[str, Any] = {}
    what_if_kinematics: Dict[str, Any] = {}
    investigative_conclusions: List[str] = []
    uncertainties_and_limitations: List[str] = []
    pdf_download_url: Optional[str] = None
    json_export_url: Optional[str] = None
    sha256_hash: Optional[str] = None
    dataset_id: Optional[str] = None
    schema_audit: Optional[Dict[str, Any]] = None
    provenance_audit: Optional[Dict[str, Any]] = None

# ====================================================================
# DATASET PROCESSING & ANALYSIS SCHEMAS
# ====================================================================

class DatasetSummaryItem(BaseModel):
    id: str
    filename: str
    sha256: str
    file_size_bytes: int
    file_size_formatted: str
    file_format: str
    dataset_type: str
    row_count: int
    col_count: int
    processing_status: str
    case_id: Optional[str] = None
    uploaded_at: str

class DatasetPreviewResponse(BaseModel):
    dataset_id: str
    filename: str
    sha256: str
    file_size_bytes: int
    file_size_formatted: str
    file_format: str
    dataset_type: str
    total_rows: int
    total_columns: int
    schema_summary: Dict[str, Any]
    preview_records: List[Dict[str, Any]]
    storage_status: str
    fips_180_4_verified: bool

class DatasetAnalysisResponse(BaseModel):
    analysis_id: str
    dataset_id: str
    scenario_id: str
    status: str
    ml_predictions: Dict[str, Any]
    reconstruction_scenario: Dict[str, Any]
    graphs: Dict[str, Any]
    provenance_audit: Dict[str, Any]

class ReportGenerateRequest(BaseModel):
    case_id: Optional[str] = "CASE_AF_8902"
    dataset_id: Optional[str] = None
    title: Optional[str] = "Automotive Incident Reconstruction & Forensic Report"
    lead_investigator: Optional[str] = "Forensic Lead Investigator"
    include_graphs: Optional[bool] = True

class ReportMetadataResponse(BaseModel):
    report_id: str
    case_id: str
    dataset_id: Optional[str] = None
    title: str
    generated_at: str
    author_id: str
    pdf_download_url: str
    json_export_url: str
    sha256_hash: str

