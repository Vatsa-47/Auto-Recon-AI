"""
AUTO-RECON AI — Model C: Event Sequence Analyzer
Analyzes chronological crash events (Sequence of Events / SOE) directly from official NHTSA FARS cevent/vevent records.
Identifies initial event, first harmful event, secondary collisions, and rollover initiation.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from backend import config

class EventSequenceAnalyzer:
    """Analyzes documented chronological sequence of events (SOE) for automotive incident reconstruction."""

    def __init__(self, cevent_csv_path: Optional[Path] = None):
        self.csv_path = cevent_csv_path or (config.BASE_DIR / "ml" / "data" / "fars2024" / "FARS2024NationalCSV" / "cevent.csv")
        self._cache: Dict[int, List[Dict[str, Any]]] = {}

    def get_events_for_case(self, st_case: int) -> List[Dict[str, Any]]:
        if st_case in self._cache:
            return self._cache[st_case]

        if not self.csv_path.exists():
            return []

        # Read only required rows matching case
        # (Using chunking or filtering for efficiency)
        matches = []
        for chunk in pd.read_csv(self.csv_path, chunksize=10000, encoding='latin1', low_memory=False):
            case_rows = chunk[chunk['ST_CASE'] == st_case]
            if not case_rows.empty:
                for _, r in case_rows.iterrows():
                    matches.append({
                        "event_number": int(r.get("EVENTNUM", 1)),
                        "vehicle_1": int(r.get("VNUMBER1", 1)) if pd.notna(r.get("VNUMBER1")) else 1,
                        "area_of_impact_1": str(r.get("AOI1NAME", "Unknown")),
                        "soe_code": int(r.get("SOE", 0)) if pd.notna(r.get("SOE")) else 0,
                        "soe_name": str(r.get("SOENAME", "Unknown Event")),
                        "vehicle_2": str(r.get("VNUMBER2NAME", "None")),
                        "area_of_impact_2": str(r.get("AOI2NAME", "None"))
                    })
        matches.sort(key=lambda x: x["event_number"])
        self._cache[st_case] = matches
        return matches

    def analyze_sequence(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Performs forensic sequence extraction and classification from chronological events."""
        if not events:
            return {
                "sequence_length": 0,
                "initial_event": "Unknown / Telemetry Not Recorded",
                "first_harmful_event": "Unknown",
                "has_rollover": False,
                "rollover_step": None,
                "has_secondary_impact": False,
                "event_pattern_classification": "UNDETERMINED_SEQUENCE",
                "chronological_milestones": []
            }

        initial_event = events[0]["soe_name"]
        first_harmful_event = None
        has_rollover = False
        rollover_step = None
        harmful_events = []
        milestones = []

        for e in events:
            step = e.get("event_number", e.get("event_num", 1))
            name = e.get("soe_name", "Unknown Event")
            aoi1 = str(e.get("area_of_impact_1", ""))

            is_non_harmful = "Non-Harmful" in aoi1 or "Non-Harmful" in name
            is_rollover = "Rollover" in name or "Overturn" in name

            if is_rollover and not has_rollover:
                has_rollover = True
                rollover_step = step

            if not is_non_harmful and first_harmful_event is None:
                first_harmful_event = name

            if not is_non_harmful:
                harmful_events.append(name)

            # Map to reconstruction milestone
            m_type = "anomaly" if is_non_harmful else ("impact" if "Motor Vehicle" in name or is_rollover else "action")
            milestones.append({
                "step": step,
                "time_offset_s": round(-3.5 + (step - 1) * 1.1, 1),
                "title": f"Step {step}: {name}",
                "impact_area": aoi1,
                "vehicle_interaction": f"Veh #{e.get('vehicle_1', 1)} -> {e.get('vehicle_2', 'Environment')}",
                "type": m_type
            })

        # Pattern classification based on event transitions
        has_secondary_impact = len(harmful_events) > 1

        pattern = "SINGLE_VEHICLE_ROADWAY_DEPARTURE"
        joined_names = " ".join([e["soe_name"] for e in events]).lower()

        if "motor vehicle in-transport" in joined_names:
            if "cross centerline" in joined_names or "front-to-front" in joined_names:
                pattern = "HEAD_ON_CENTERLINE_CROSSING"
            elif "rear" in joined_names:
                pattern = "REAR_END_COLLISION"
            elif has_secondary_impact:
                pattern = "MULTI_VEHICLE_PRIMARY_AND_SECONDARY_COLLISION"
            else:
                pattern = "MULTI_VEHICLE_COLLISION"
        elif has_rollover:
            pattern = "RUN_OFF_ROAD_ROLLOVER"
        elif "pedestrian" in joined_names:
            pattern = "PEDESTRIAN_IMPACT"
        elif "tree" in joined_names or "pole" in joined_names:
            pattern = "FIXED_OBJECT_OFF_ROADWAY_IMPACT"

        return {
            "sequence_length": len(events),
            "initial_event": initial_event,
            "first_harmful_event": first_harmful_event or initial_event,
            "has_rollover": has_rollover,
            "rollover_step": rollover_step,
            "has_secondary_impact": has_secondary_impact,
            "harmful_event_count": len(harmful_events),
            "event_pattern_classification": pattern,
            "chronological_milestones": milestones
        }

_analyzer_instance: Optional[EventSequenceAnalyzer] = None

def get_event_analyzer() -> EventSequenceAnalyzer:
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = EventSequenceAnalyzer()
    return _analyzer_instance
