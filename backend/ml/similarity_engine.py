"""
AUTO-RECON AI — Model D: Historical Crash Similarity Matching Engine
Retrieves comparable historical FARS crash records based on physical parameters, collision geometry, and road conditions.
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List, Optional
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer

from backend import config
from backend.ml.dataset import SEVERITY_CLASSES

_similarity_cache: Dict[str, Any] = {}

class ScenarioSimilarityEngine:
    def __init__(self, data_path: Optional[Path] = None, save_dir: Optional[Path] = None):
        self.target_dir = save_dir or config.ML_MODELS_DIR
        self.csv_path = data_path or (self.target_dir / "fars_2024_national_dataset.csv")
        self.nn_model: Optional[NearestNeighbors] = None
        self.preprocessor: Optional[ColumnTransformer] = None
        self.df: Optional[pd.DataFrame] = None
        self._initialize()

    def _initialize(self):
        index_file = self.target_dir / "similarity_index.joblib"
        prep_file = self.target_dir / "similarity_preprocessor.joblib"

        if index_file.exists() and prep_file.exists() and self.csv_path.exists():
            self.nn_model = joblib.load(index_file)
            self.preprocessor = joblib.load(prep_file)
            self.df = pd.read_csv(self.csv_path)
            return

        if not self.csv_path.exists():
            from backend.ml.dataset import get_or_create_fars_dataset
            get_or_create_fars_dataset(self.csv_path)

        self.df = pd.read_csv(self.csv_path)

        cont_features = ["pre_impact_speed_kph", "delta_v_kph"]
        cat_features = [
            "collision_type", "road_condition", "vehicle_weight_class",
            "seatbelt_latched", "airbag_deployed"
        ]

        self.preprocessor = ColumnTransformer([
            ("num", StandardScaler(), cont_features),
            ("cat", OneHotEncoder(sparse_output=False, handle_unknown="ignore"), cat_features)
        ])

        X_trans = self.preprocessor.fit_transform(self.df)
        self.nn_model = NearestNeighbors(n_neighbors=10, metric="cosine")
        self.nn_model.fit(X_trans)

        joblib.dump(self.nn_model, index_file)
        joblib.dump(self.preprocessor, prep_file)

    def find_similar_crashes(
        self,
        pre_impact_speed_kph: float,
        delta_v_kph: float,
        collision_type: str = "ANGLE",
        road_condition: str = "DRY",
        vehicle_weight_class: str = "SEDAN",
        seatbelt_latched: bool = True,
        airbag_deployed: bool = True,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        if self.nn_model is None or self.preprocessor is None or self.df is None:
            self._initialize()

        query_df = pd.DataFrame([{
            "pre_impact_speed_kph": float(pre_impact_speed_kph),
            "delta_v_kph": float(delta_v_kph),
            "collision_type": collision_type.strip().upper(),
            "road_condition": road_condition.strip().upper(),
            "vehicle_weight_class": vehicle_weight_class.strip().upper(),
            "seatbelt_latched": 1 if seatbelt_latched else 0,
            "airbag_deployed": 1 if airbag_deployed else 0
        }])

        q_trans = self.preprocessor.transform(query_df)
        distances, indices = self.nn_model.kneighbors(q_trans, n_neighbors=top_k)

        results = []
        for rank, (dist, idx) in enumerate(zip(distances[0], indices[0]), 1):
            row = self.df.iloc[idx]
            similarity_pct = round(max(0.0, (1.0 - float(dist)) * 100.0), 1)
            sev_idx = int(row.get("injury_severity", 0))
            sev_label = SEVERITY_CLASSES[sev_idx] if 0 <= sev_idx < len(SEVERITY_CLASSES) else "UNKNOWN"

            results.append({
                "rank": rank,
                "dataset_index": int(idx),
                "similarity_score": similarity_pct,
                "collision_type": str(row.get("collision_type")),
                "pre_impact_speed_kph": float(row.get("pre_impact_speed_kph", 0)),
                "delta_v_kph": float(row.get("delta_v_kph", 0)),
                "road_condition": str(row.get("road_condition")),
                "vehicle_weight_class": str(row.get("vehicle_weight_class")),
                "injury_severity_outcome": sev_label,
                "comparable_factors": [
                    f"Kinematic similarity: {similarity_pct}%",
                    f"Geometry: {row.get('collision_type')} on {row.get('road_condition')} surface",
                    f"Approach velocity: {row.get('pre_impact_speed_kph')} km/h (Delta-V: {row.get('delta_v_kph')} km/h)"
                ]
            })

        return results

_engine_instance: Optional[ScenarioSimilarityEngine] = None

def get_similarity_engine() -> ScenarioSimilarityEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ScenarioSimilarityEngine()
    return _engine_instance
