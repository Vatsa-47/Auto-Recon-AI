"""
AUTO-RECON AI — External Model Storage & Artifact Manager
Enables loading AI model artifacts from external cloud storage (GCS, S3, HTTPS)
or dedicated mounted volumes, keeping the serverless deployment bundle ultra-lean (< 50 MB)
while ensuring local environments fall back seamlessly to local ML_MODELS_DIR.
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from backend import config

logger = logging.getLogger("autorecon.model_storage")

REQUIRED_MODEL_FILES = [
    "crash_severity_pytorch.pt",
    "baseline_sklearn.joblib",
    "preprocessor.joblib",
    "pattern_classifier.joblib",
    "similarity_index.joblib",
    "model_metadata.json",
    "fars_2024_national_dataset.csv"
]

def get_effective_models_dir() -> Path:
    """
    Returns the active models directory.
    If AUTORECON_MODELS_DIR is specified, uses that path.
    If running in a constrained serverless environment where models were kept
    external, downloads/caches them into /tmp/autorecon_models.
    Otherwise falls back to the default config.ML_MODELS_DIR.
    """
    custom_dir = os.getenv("AUTORECON_MODELS_DIR")
    if custom_dir:
        p = Path(custom_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # If local models exist in backend/ml/saved_models, use them
    local_dir = config.ML_MODELS_DIR
    if all((local_dir / f).exists() for f in ["crash_severity_pytorch.pt", "baseline_sklearn.joblib"]):
        return local_dir

    # If local models are missing and external URL is configured, download to /tmp
    external_base_url = os.getenv("AUTORECON_EXTERNAL_MODELS_URL")
    if external_base_url:
        tmp_dir = Path("/tmp/autorecon_models")
        tmp_dir.mkdir(parents=True, exist_ok=True)
        _sync_models_from_external(external_base_url, tmp_dir)
        return tmp_dir

    return local_dir

def _sync_models_from_external(base_url: str, dest_dir: Path):
    """Downloads model artifacts from an external HTTP/GCS/S3 storage URL."""
    import urllib.request
    base_url = base_url.rstrip("/")
    for filename in REQUIRED_MODEL_FILES:
        target_path = dest_dir / filename
        if target_path.exists():
            continue
        source_url = f"{base_url}/{filename}"
        logger.info(f"Downloading model artifact from {source_url} to {target_path}...")
        try:
            urllib.request.urlretrieve(source_url, target_path)
            logger.info(f"Successfully downloaded {filename}")
        except Exception as e:
            logger.warning(f"Could not download {filename} from {source_url}: {e}")
