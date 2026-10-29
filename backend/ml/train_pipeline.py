"""
AUTO-RECON AI — Reproducible PyTorch & Scikit-learn Training Pipeline
Trains and benchmarks models on official NHTSA FARS 2024 National Data.
Computes test metrics: Accuracy, Macro/Weighted F1, Confusion Matrix, and Class-Wise Metrics.
Persists weights, preprocessors, and metadata, and updates MySQL ml_models table.
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
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
from sklearn.utils.class_weight import compute_class_weight

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader

from backend import config
from backend.database import get_session_factory, MLModelRecord
from backend.ml.dataset import get_or_create_fars_dataset, SEVERITY_CLASSES
from backend.ml.model import CrashSeverityNet

def run_training_pipeline(
    save_dir: Optional[Path] = None,
    fars_data_dir: Optional[Path] = None,
    epochs: int = 15,
    batch_size: int = 64
) -> Dict[str, Any]:
    save_path = save_dir or config.ML_MODELS_DIR
    save_path.mkdir(parents=True, exist_ok=True)

    csv_cache = save_path / "fars_2024_national_dataset.csv"
    print(f"[*] Ingesting FARS 2024 dataset (cache: {csv_cache})...")
    df = get_or_create_fars_dataset(csv_cache, raw_data_dir=fars_data_dir)

    print(f"[+] Dataset loaded: {len(df)} records across {len(df.columns)} columns.")
    print(f"[*] Target distribution: {dict(df['injury_severity'].value_counts())}")

    X = df.drop(columns=["injury_severity"])
    y = df["injury_severity"].values.astype(int)

    continuous_features = ["pre_impact_speed_kph", "delta_v_kph"]
    categorical_features = [
        "brake_applied", "seatbelt_latched", "airbag_deployed",
        "collision_type", "road_condition", "vehicle_weight_class"
    ]

    # Preprocessing pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), continuous_features),
            ("cat", OneHotEncoder(sparse_output=False, handle_unknown="ignore"), categorical_features)
        ]
    )

    # 70% Train, 15% Validation, 15% Test (stratified to ensure identical class distributions)
    X_train_raw, X_temp_raw, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val_raw, X_test_raw, y_val, y_test = train_test_split(
        X_temp_raw, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"[*] Split sizes: Train={len(X_train_raw)}, Val={len(X_val_raw)}, Test={len(X_test_raw)}")

    # Fit preprocessor strictly on training data (prevent data leakage)
    X_train = preprocessor.fit_transform(X_train_raw)
    X_val = preprocessor.transform(X_val_raw)
    X_test = preprocessor.transform(X_test_raw)

    input_dim = X_train.shape[1]
    num_classes = len(SEVERITY_CLASSES)

    # =========================================================================
    # 1. TRAIN SCIKIT-LEARN BASELINE (Random Forest Classifier)
    # =========================================================================
    print("[*] Training Scikit-learn Random Forest Baseline...")
    rf_baseline = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_baseline.fit(X_train, y_train)

    rf_preds = rf_baseline.predict(X_test)
    rf_acc = float(accuracy_score(y_test, rf_preds))
    rf_macro_f1 = float(f1_score(y_test, rf_preds, average="macro"))
    rf_weighted_f1 = float(f1_score(y_test, rf_preds, average="weighted"))
    rf_cm = confusion_matrix(y_test, rf_preds).tolist()
    rf_report = classification_report(
        y_test, rf_preds, target_names=SEVERITY_CLASSES, output_dict=True
    )

    print(f"[+] Baseline Scikit-learn Test Accuracy: {rf_acc*100:.2f}%, Macro F1: {rf_macro_f1*100:.2f}%")

    # =========================================================================
    # 2. TRAIN PYTORCH DEEP NEURAL NETWORK (CrashSeverityNet)
    # =========================================================================
    print(f"[*] Training PyTorch CrashSeverityNet (input_dim={input_dim}, classes={num_classes})...")
    torch.manual_seed(42)
    pytorch_model = CrashSeverityNet(input_dim=input_dim, num_classes=num_classes)

    # Balanced class weights for cross-entropy loss
    class_weights = compute_class_weight("balanced", classes=np.unique(y_train), y=y_train)
    weights_tensor = torch.tensor(class_weights, dtype=torch.float32)

    criterion = nn.CrossEntropyLoss(weight=weights_tensor)
    optimizer = optim.Adam(pytorch_model.parameters(), lr=0.003, weight_decay=1e-4)

    train_tensor_x = torch.tensor(X_train, dtype=torch.float32)
    train_tensor_y = torch.tensor(y_train, dtype=torch.long)
    val_tensor_x = torch.tensor(X_val, dtype=torch.float32)
    val_tensor_y = torch.tensor(y_val, dtype=torch.long)
    test_tensor_x = torch.tensor(X_test, dtype=torch.float32)
    test_tensor_y = torch.tensor(y_test, dtype=torch.long)

    train_loader = DataLoader(
        TensorDataset(train_tensor_x, train_tensor_y),
        batch_size=batch_size,
        shuffle=True
    )

    for epoch in range(epochs):
        pytorch_model.train()
        total_loss = 0.0
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = pytorch_model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(batch_y)

        # Validation loss check
        pytorch_model.eval()
        with torch.no_grad():
            val_outputs = pytorch_model(val_tensor_x)
            val_loss = criterion(val_outputs, val_tensor_y).item()

        if (epoch + 1) % 5 == 0 or epoch == epochs - 1:
            print(f"    Epoch {epoch+1:02d}/{epochs:02d} - Train Loss: {total_loss/len(X_train):.4f} - Val Loss: {val_loss:.4f}")

    # Evaluate PyTorch Model on Test Set
    pytorch_model.eval()
    with torch.no_grad():
        test_logits = pytorch_model(test_tensor_x)
        test_loss = float(criterion(test_logits, test_tensor_y).item())
        test_preds = torch.argmax(test_logits, dim=-1).numpy()

    pytorch_acc = float(accuracy_score(y_test, test_preds))
    pytorch_macro_f1 = float(f1_score(y_test, test_preds, average="macro"))
    pytorch_weighted_f1 = float(f1_score(y_test, test_preds, average="weighted"))
    pytorch_cm = confusion_matrix(y_test, test_preds).tolist()
    pytorch_report = classification_report(
        y_test, test_preds, target_names=SEVERITY_CLASSES, output_dict=True
    )

    print(f"[+] PyTorch Test Accuracy: {pytorch_acc*100:.2f}%, Macro F1: {pytorch_macro_f1*100:.2f}%, Test Loss: {test_loss:.4f}")

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
        "dataset_name": "NHTSA Fatality Analysis Reporting System (FARS) 2024 National Release",
        "dataset_year": 2024,
        "source_url": "https://static.nhtsa.gov/nhtsa/downloads/FARS/2024/National/FARS2024NationalCSV.zip",
        "target_variable": "injury_severity (KABCO 4-Class Scale)",
        "classes": SEVERITY_CLASSES,
        "sample_count": len(df),
        "train_samples": len(X_train_raw),
        "val_samples": len(X_val_raw),
        "test_samples": len(X_test_raw),
        "input_dim": input_dim,
        "num_classes": num_classes,
        "continuous_features": continuous_features,
        "categorical_features": categorical_features,
        "pytorch_evaluation": {
            "accuracy": pytorch_acc,
            "macro_f1": pytorch_macro_f1,
            "weighted_f1": pytorch_weighted_f1,
            "test_loss": test_loss,
            "confusion_matrix": pytorch_cm,
            "classification_report": pytorch_report
        },
        "baseline_evaluation": {
            "model_type": "RandomForestClassifier",
            "accuracy": rf_acc,
            "macro_f1": rf_macro_f1,
            "weighted_f1": rf_weighted_f1,
            "confusion_matrix": rf_cm,
            "classification_report": rf_report
        },
        "limitations": [
            "FARS census records fatal incidents; non-fatal outcomes represent vehicles involved in fatal collisions.",
            "Crash velocity change (Delta-V) is estimated via Campbell crush energy mechanics and impact geometry.",
            "Predictions reflect statistical risk heuristics and do not substitute for on-site physical reconstruction."
        ],
        "trained_at": datetime.now(timezone.utc).isoformat()
    }

    meta_path = save_path / "model_metadata.json"
    with open(meta_path, "w") as f:
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
                    version="2.0.0",
                    framework="PyTorch 2.x",
                    task="KABCO Crash Injury Severity Estimation",
                    dataset_name="NHTSA FARS 2024 National Census",
                    accuracy=pytorch_acc,
                    f1_score=pytorch_macro_f1,
                    loss=test_loss,
                    model_path=str(torch_path),
                    metadata_json=json.dumps(meta)
                )
                session.add(pt_record)
            else:
                pt_record.version = "2.0.0"
                pt_record.dataset_name = "NHTSA FARS 2024 National Census"
                pt_record.accuracy = pytorch_acc
                pt_record.f1_score = pytorch_macro_f1
                pt_record.loss = test_loss
                pt_record.metadata_json = json.dumps(meta)

            # Register Scikit-learn Baseline
            sk_record = session.query(MLModelRecord).filter_by(id="ML_SKLEARN_BASELINE_V1").first()
            if not sk_record:
                sk_record = MLModelRecord(
                    id="ML_SKLEARN_BASELINE_V1",
                    name="Random Forest Baseline Classifier",
                    version="2.0.0",
                    framework="Scikit-learn",
                    task="KABCO Baseline Comparison",
                    dataset_name="NHTSA FARS 2024 National Census",
                    accuracy=rf_acc,
                    f1_score=rf_macro_f1,
                    loss=None,
                    model_path=str(sklearn_path),
                    metadata_json=json.dumps(meta)
                )
                session.add(sk_record)
            else:
                sk_record.version = "2.0.0"
                sk_record.dataset_name = "NHTSA FARS 2024 National Census"
                sk_record.accuracy = rf_acc
                sk_record.f1_score = rf_macro_f1
                sk_record.metadata_json = json.dumps(meta)

            session.commit()
            print("[+] Updated MySQL autorecon ml_models records with live FARS 2024 evaluation metrics.")
    except Exception as e:
        print(f"[!] Warning updating MySQL ml_models table: {e}")

    return meta

if __name__ == "__main__":
    run_training_pipeline()
