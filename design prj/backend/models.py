from pydantic import BaseModel, Field, field_validator, field_serializer, ConfigDict
from typing import Optional, List, Union
from datetime import datetime
import re

HEX64_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

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
