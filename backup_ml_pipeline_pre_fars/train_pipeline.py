"""
AUTO-RECON AI — Reproducible PyTorch & Scikit-learn Training Pipeline
Evaluates held-out FARS/NHTSA test data and persists weights & metadata.
"""

import os
import json
import joblib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

from backend import config
from backend.database import get_session_factory, MLModelRecord
from backend.ml.dataset import get_or_create_fars_dataset, SEVERITY_CLASSES
from backend.ml.model import CrashSeverityNet

def run_training_pipeline(save_dir: Optional[Path] = None) -> Dict[str, Any]:
    save_path = save_dir or config.ML_MODELS_DIR
    save_path.mkdir(parents=True, exist_ok=True)

    csv_cache = save_path / "fars_nhtsa_calibrated_callset.csv"
    df = get_or_create_fars_dataset(csv_cache)

    X = df.drop(columns=["injury_severity"])
    y = df["injury_severity"].values

    continuous_features = ["pre_impact_speed_kph", "delta_v_kph"]
    categorical_features = ["brake_applied", "seatbelt_latched", "airbag_deployed", "collision_type", "road_condition", "vehicle_weight_class"]

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), continuous_features),
            ("cat", OneHotEncoder(sparse_output=False, handle_unknown="ignore"), categorical_features)
        ]
    )

    # 70% Train, 15% Validation, 15% Test
    X_train_raw, X_temp_raw, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val_raw, X_test_raw, y_val, y_test = train_test_split(X_temp_raw, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    # Fit preprocessor strictly on training data
    X_train = preprocessor.fit_transform(X_train_raw)
    X_val = preprocessor.transform(X_val_raw)
    X_test = preprocessor.transform(X_test_raw)

    input_dim = X_train.shape[1]
    num_classes = len(SEVERITY_CLASSES)

    # =========================================================================
    # 1. TRAIN PYTORCH MODEL
    # =========================================================================
    torch.manual_seed(42)
    pytorch_model = CrashSeverityNet(input_dim=input_dim, num_classes=num_classes)

    train_tensor_x = torch.tensor(X_train, dtype=torch.float32)
    train_tensor_y = torch.tensor(y_train, dtype=torch.long)
    val_tensor_x = torch.tensor(X_val, dtype=torch.float32)
    val_tensor_y = torch.tensor(y_val, dtype=torch.long)
    test_tensor_x = torch.tensor(X_test, dtype=torch.float32)
    test_tensor_y = torch.tensor(y_test, dtype=torch.long)

    train_loader = DataLoader(TensorDataset(train_tensor_x, train_tensor_y), batch_size=32, shuffle=True)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(pytorch_model.parameters(), lr=0.003, weight_decay=1e-4)

    epochs = 25
    for epoch in range(epochs):
        pytorch_model.train()
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = pytorch_model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

    # Evaluate PyTorch Model on Test Set
    pytorch_model.eval()
    with torch.no_grad():
        test_logits = pytorch_model(test_tensor_x)
        test_loss = criterion(test_logits, test_tensor_y).item()
        test_preds = torch.argmax(test_logits, dim=-1).numpy()

    pytorch_acc = float(accuracy_score(y_test, test_preds))
    pytorch_f1 = float(f1_score(y_test, test_preds, average="macro"))

    # =========================================================================
    # 2. TRAIN SCIKIT-LEARN BASELINE (Random Forest)
    # =========================================================================
    rf_baseline = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    rf_baseline.fit(X_train, y_train)
    rf_preds = rf_baseline.predict(X_test)

    rf_acc = float(accuracy_score(y_test, rf_preds))
    rf_f1 = float(f1_score(y_test, rf_preds, average="macro"))

    # =========================================================================
    # 3. SAVE ARTIFACTS
    # =========================================================================
    torch_path = save_path / "crash_severity_pytorch.pt"
    torch.save(pytorch_model.state_dict(), torch_path)

    sklearn_path = save_path / "baseline_sklearn.joblib"
    joblib.dump(rf_baseline, sklearn_path)

    preproc_path = save_path / "preprocessor.joblib"
    joblib.dump(preprocessor, preproc_path)

    meta = {
        "input_dim": input_dim,
        "num_classes": num_classes,
        "continuous_features": continuous_features,
        "categorical_features": categorical_features,
        "pytorch_accuracy": pytorch_acc,
        "pytorch_macro_f1": pytorch_f1,
        "pytorch_test_loss": test_loss,
        "baseline_accuracy": rf_acc,
        "baseline_macro_f1": rf_f1,
        "sample_count": len(df),
        "trained_at": datetime.now(timezone.utc).isoformat()
    }
    with open(save_path / "model_metadata.json", "w") as f:
        json.dump(meta, f, indent=2)

    # =========================================================================
    # 4. RECORD IN MYSQL DATABASE
    # =========================================================================
    try:
        factory = get_session_factory()
        with factory() as session:
            # Register PyTorch Model
            pt_record = session.query(MLModelRecord).filter_by(id="ML_PYTORCH_SEVERITY_V1").first()
            if not pt_record:
                pt_record = MLModelRecord(
                    id="ML_PYTORCH_SEVERITY_V1",
                    name="AUTO-RECON Deep Severity Net",
                    version="1.0.0",
                    framework="PyTorch 2.x",
                    task="KABCO Crash Injury Severity Estimation",
                    dataset_name="NHTSA FARS / CISS Calibrated Callset",
                    accuracy=pytorch_acc,
                    f1_score=pytorch_f1,
                    loss=test_loss,
                    model_path=str(torch_path),
                    metadata_json=json.dumps(meta)
                )
                session.add(pt_record)
            else:
                pt_record.accuracy = pytorch_acc
                pt_record.f1_score = pytorch_f1
                pt_record.loss = test_loss
                pt_record.metadata_json = json.dumps(meta)

            # Register Scikit-learn Baseline
            sk_record = session.query(MLModelRecord).filter_by(id="ML_SKLEARN_BASELINE_V1").first()
            if not sk_record:
                sk_record = MLModelRecord(
                    id="ML_SKLEARN_BASELINE_V1",
                    name="Random Forest Baseline Classifier",
                    version="1.0.0",
                    framework="Scikit-learn",
                    task="KABCO Baseline Comparison",
                    dataset_name="NHTSA FARS / CISS Calibrated Callset",
                    accuracy=rf_acc,
                    f1_score=rf_f1,
                    loss=None,
                    model_path=str(sklearn_path),
                    metadata_json=json.dumps(meta)
                )
                session.add(sk_record)
            else:
                sk_record.accuracy = rf_acc
                sk_record.f1_score = rf_f1

            session.commit()
    except Exception as e:
        print(f"[!] Warning updating MySQL ml_models table: {e}")

    print(f"[+] PyTorch CrashSeverityNet trained: Acc={pytorch_acc*100:.2f}%, F1={pytorch_f1*100:.2f}%, Loss={test_loss:.4f}")
    print(f"[+] Scikit-learn Baseline trained : Acc={rf_acc*100:.2f}%, F1={rf_f1*100:.2f}%")
    return meta

if __name__ == "__main__":
    run_training_pipeline()
