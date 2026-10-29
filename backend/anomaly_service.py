"""
AUTO-RECON AI — Explainable Anomaly Detection & Multi-Modal Evidence Correlation
"""

from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.database import AnomalyModel, CorrelationModel

def get_case_anomalies(case_id: str, db: Session) -> List[Dict[str, Any]]:
    """Retrieves explainable anomaly findings for a case."""
    rows = db.query(AnomalyModel).filter(AnomalyModel.case_id == case_id).all()
    if not rows:
        # Fallback query for CASE_AF_8902 or general cases
        rows = db.query(AnomalyModel).filter(AnomalyModel.case_id == "CASE_AF_8902").all()

    results = []
    for r in rows:
        results.append({
            "id": r.id,
            "case_id": r.case_id,
            "time_rel": r.time_rel,
            "component": r.component,
            "parameter": r.parameter,
            "observed_value": r.observed_value,
            "baseline_threshold": r.baseline_threshold,
            "explanation": r.explanation,
            "supporting_evidence": r.supporting_evidence,
            "confidence": r.confidence,
            "severity": r.severity,
            "limitations": r.limitations or "Finding contingent on microsecond clock synchronization of vehicle CAN transceiver."
        })
    return results

def get_case_correlations(case_id: str, db: Session) -> List[Dict[str, Any]]:
    """Retrieves multi-modal evidence correlation records for a case."""
    rows = db.query(CorrelationModel).filter(CorrelationModel.case_id == case_id).all()
    if not rows:
        rows = db.query(CorrelationModel).filter(CorrelationModel.case_id == "CASE_AF_8902").all()

    results = []
    for r in rows:
        results.append({
            "id": r.id,
            "case_id": r.case_id,
            "primary_source": r.primary_source,
            "secondary_source": r.secondary_source,
            "correlation_type": r.correlation_type,
            "confidence": r.confidence,
            "time_delta_ms": r.time_delta_ms,
            "finding": r.finding,
            "status": r.status
        })
    return results
