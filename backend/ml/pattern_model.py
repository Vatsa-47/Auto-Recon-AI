"""
AUTO-RECON AI — Model B: Crash Pattern Classifier
Predicts crash pattern / collision geometry (FRONTAL, ANGLE, REAR, ROLLOVER, SIDESWIPE)
Trained on official NHTSA FARS 2024 National Crash Census data.
"""

import json
import joblib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report

from backend import config
from backend.database import get_session_factory, MLModelRecord

PATTERN_CLASSES = ["FRONTAL", "ANGLE", "REAR", "ROLLOVER", "SIDESWIPE"]

_pattern_cache: Dict[str, Any] = {}

def train_pattern_classifier(
    data_path: Optional[Path] = None,
    save_dir: Optional[Path] = None
) -> Dict[str, Any]:
    target_dir = save_dir or config.ML_MODELS_DIR
    csv_file = data_path or (target_dir / "fars_2024_national_dataset.csv")

    if not csv_file.exists():
        from backend.ml.dataset import get_or_create_fars_dataset
        get_or_create_fars_dataset(csv_file)

    df = pd.read_csv(csv_file)
    X = df.drop(columns=["collision_type", "injury_severity"])
    y = df["collision_type"].values

    continuous_features = ["pre_impact_speed_kph", "delta_v_kph"]
    categorical_features = [
        "brake_applied", "seatbelt_latched", "airbag_deployed",
        "road_condition", "vehicle_weight_class"
    ]

    preprocessor = ColumnTransformer([
        ("num", StandardScaler(), continuous_features),
        ("cat", OneHotEncoder(sparse_output=False, handle_unknown="ignore"), categorical_features)
    ])

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    X_train = preprocessor.fit_transform(X_train_raw)
    X_test = preprocessor.transform(X_test_raw)

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)

    acc = float(accuracy_score(y_test, preds))
    macro_f1 = float(f1_score(y_test, preds, average="macro"))
    weighted_f1 = float(f1_score(y_test, preds, average="weighted"))
    cm = confusion_matrix(y_test, preds).tolist()
    report = classification_report(y_test, preds, output_dict=True)

    # Save artifacts
    model_path = target_dir / "pattern_classifier.joblib"
    prep_path = target_dir / "pattern_preprocessor.joblib"
    joblib.dump(model, model_path)
    joblib.dump(preprocessor, prep_path)

    metrics = {
        "model_name": "Random Forest Crash Pattern Classifier",
        "task": "Collision Pattern Classification (FRONTAL, ANGLE, REAR, SIDESWIPE, ROLLOVER)",
        "dataset_name": "NHTSA FARS 2024 National Census",
        "test_samples": len(y_test),
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "confusion_matrix": cm,
        "classes": list(model.classes_),
        "trained_at": datetime.now(timezone.utc).isoformat()
    }

    # Register in MySQL
    try:
        factory = get_session_factory()
        with factory() as session:
            rec = session.query(MLModelRecord).filter_by(id="ML_SKLEARN_PATTERN_V1").first()
            if not rec:
                rec = MLModelRecord(
                    id="ML_SKLEARN_PATTERN_V1",
                    name="Random Forest Crash Pattern Classifier",
                    version="1.0.0",
                    framework="Scikit-learn",
                    task="Collision Geometry & Pattern Attribution",
                    dataset_name="NHTSA FARS 2024 National Census",
                    accuracy=acc,
                    f1_score=macro_f1,
                    loss=None,
                    model_path=str(model_path),
                    metadata_json=json.dumps(metrics)
                )
                session.add(rec)
            else:
                rec.accuracy = acc
                rec.f1_score = macro_f1
                rec.metadata_json = json.dumps(metrics)
            session.commit()
    except Exception as e:
        print(f"[!] Warning registering pattern model in MySQL: {e}")

    print(f"[+] Model B (Crash Pattern) trained: Acc={acc*100:.2f}%, Macro F1={macro_f1*100:.2f}%")
    return metrics

def get_pattern_artifacts(save_dir: Optional[Path] = None):
    global _pattern_cache
    target_dir = save_dir or config.ML_MODELS_DIR
    if "model" in _pattern_cache:
        return _pattern_cache

    model_path = target_dir / "pattern_classifier.joblib"
    prep_path = target_dir / "pattern_preprocessor.joblib"

    if not (model_path.exists() and prep_path.exists()):
        train_pattern_classifier(save_dir=target_dir)

    _pattern_cache = {
        "model": joblib.load(model_path),
        "preprocessor": joblib.load(prep_path)
    }
    return _pattern_cache

def predict_crash_pattern(
    pre_impact_speed_kph: float,
    delta_v_kph: float,
    brake_applied: bool = True,
    seatbelt_latched: bool = True,
    airbag_deployed: bool = True,
    road_condition: str = "DRY",
    vehicle_weight_class: str = "SEDAN"
) -> Dict[str, Any]:
    artifacts = get_pattern_artifacts()
    model = artifacts["model"]
    preprocessor = artifacts["preprocessor"]

    input_df = pd.DataFrame([{
        "pre_impact_speed_kph": float(pre_impact_speed_kph),
        "delta_v_kph": float(delta_v_kph),
        "brake_applied": 1 if brake_applied else 0,
        "seatbelt_latched": 1 if seatbelt_latched else 0,
        "airbag_deployed": 1 if airbag_deployed else 0,
        "road_condition": road_condition.strip().upper(),
        "vehicle_weight_class": vehicle_weight_class.strip().upper()
    }])

    X_trans = preprocessor.transform(input_df)
    probs = model.predict_proba(X_trans)[0]
    classes = list(model.classes_)
    best_idx = int(np.argmax(probs))
    best_pattern = classes[best_idx]
    confidence = float(probs[best_idx])

    return {
        "predicted_pattern": best_pattern,
        "confidence": round(confidence, 3),
        "pattern_probabilities": {
            classes[i]: round(float(probs[i]), 4) for i in range(len(classes))
        },
        "model_framework": "Scikit-learn Random Forest (Balanced Class Weights)",
        "dataset_provenance": "NHTSA FARS 2024 National Census"
    }

if __name__ == "__main__":
    train_pattern_classifier()
