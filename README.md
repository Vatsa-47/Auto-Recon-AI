# AUTO-RECON AI: AI-Driven Incident Reconstruction for Automotive Digital Forensics

> **Automotive Digital Forensics, 49 CFR Part 563 EDR Extraction, PyTorch Incident Reconstruction & Cryptographic Chain-of-Custody Ledger (MySQL 8.0 & FastAPI)**

![Python](https://img.shields.io/badge/Python-3.12-3776ab?style=for-the-badge&logo=python&logoColor=white)
![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Uvicorn-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Machine Learning](https://img.shields.io/badge/ML-PyTorch%20%7C%20Scikit--Learn-ee4c2c?style=for-the-badge&logo=pytorch&logoColor=white)
![Database](https://img.shields.io/badge/Database-MySQL%208.0%20%7C%20SQLAlchemy%202.x-0284c7?style=for-the-badge&logo=mysql&logoColor=white)
![Security](https://img.shields.io/badge/Security-FIPS%20180--4%20SHA--256%20%7C%20Hash--Chaining-7c3aed?style=for-the-badge)
![Compliance](https://img.shields.io/badge/Regulation-49%20CFR%20Part%20563%20%7C%20ISO%2026021-10b981?style=for-the-badge)

---

## 📌 Architecture Overview & Single Primary Backend

AUTO-RECON AI has migrated to **Python 3.12, FastAPI, PyTorch, and MySQL 8.0** as its single, authoritative backend engine (`backend/`).
- **Spring Boot is no longer required**: The legacy Java backend in `spring-backend/` is deprecated and preserved strictly for historical reference. The frontend (`app.js`) is directly integrated with FastAPI on `http://127.0.0.1:8000/api`.
- **Authoritative Database**: MySQL database **`autorecon`**. SQLite is not used in production and silent fallback is strictly prohibited.
- **Machine Learning**: Deep Multi-Layer Perceptron neural network (`CrashSeverityNet`) built in **PyTorch** with a **Scikit-learn** Random Forest baseline, trained on calibrated NHTSA / FARS crash datasets for collision severity and trajectory risk estimation.
- **Regulatory Framework**: Standardized around **Title 49 CFR Part 563** (NHTSA Event Data Recorder requirements) for Table 1 and Table 2 pre-crash time-history intervals and crash pulse recording.

---

## 🏗️ MySQL 8.0 Setup & Configuration

### 1. Prerequisites
- **MySQL Server 8.0+** running locally on port 3306.
- **Python 3.12+**.
- Modern web browser (Chrome, Edge, Firefox).

---

### 2. Database & Application User Setup

The database name is **`autorecon`**. For Principle of Least Privilege, a dedicated non-root user `autorecon_app` is used.

Run the provided SQL script using the MySQL client:
```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p < database/setup.sql
```

Or execute directly in the MySQL Shell:
```sql
CREATE DATABASE IF NOT EXISTS autorecon 
  CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'autorecon_app'@'localhost' IDENTIFIED BY 'autorecon_secure_password_2026';
CREATE USER IF NOT EXISTS 'autorecon_app'@'127.0.0.1' IDENTIFIED BY 'autorecon_secure_password_2026';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES 
  ON autorecon.* TO 'autorecon_app'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES 
  ON autorecon.* TO 'autorecon_app'@'127.0.0.1';

FLUSH PRIVILEGES;
```

---

### 3. Environment Variables (`.env`)

Configure the `.env` file in the project root:
```ini
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=autorecon
DB_USER=autorecon_app
DB_PASSWORD=autorecon_secure_password_2026

# Storage Directory for Tamper-Resistant Forensic Evidence
AUTORECON_STORAGE_DIR=backend/storage

# API Server Configuration
API_HOST=127.0.0.1
API_PORT=8000
```

---

### 4. Dependency Installation

Install dependencies using pip:
```powershell
pip install -r backend/requirements.txt
```

---

### 5. Train the PyTorch & Scikit-learn Pipeline

Run the reproducible training script to train the neural network and baseline model, evaluate on held-out FARS/NHTSA test data, and store model metadata in MySQL:
```powershell
python -m backend.ml.train_pipeline
```
- **PyTorch Model**: `backend/ml/saved_models/crash_severity_pytorch.pt` (Accuracy: ~83.2%, Macro F1: ~71.0%)
- **Baseline Model**: `backend/ml/saved_models/baseline_sklearn.joblib` (Accuracy: ~82.9%, Macro F1: ~66.0%)

---

### 6. Start the FastAPI Application Backend

Start the Uvicorn server:
```powershell
uvicorn backend.main:app --reload --port 8000
```
- **API Base**: `http://127.0.0.1:8000/api`
- **Interactive OpenAPI Documentation (Swagger UI)**: `http://127.0.0.1:8000/docs`
- **Health Check Endpoint**: `http://127.0.0.1:8000/api/health`

---

### 7. Run Test Suite

Run the full pytest test suite (34 automated unit and integration tests):
```powershell
pytest backend/tests/ -v
```

---

### 8. Open the Remote Forensic Dashboard

Launch `index.html` in your web browser:
```powershell
start index.html
```
The dashboard automatically connects to `http://127.0.0.1:8000/api` and displays:
- **Status Pill**: `Backend Online (FastAPI + PyTorch Engine)`
- **Chain of Custody**: Cryptographic verification against MySQL
- **Reconstruction Studio**: Synchronized Top View, Dashcam, and 3D Trajectory
- **What-If Simulation**: Counterfactual latency physics simulation
- **Forensic Report**: Exhaustive legal report generator

---

## 🔐 Cryptographic Chain-of-Custody & Evidence Ledger

The Evidence Ledger enforces digital forensic integrity:
1. **Streaming SHA-256 Hashing**: Uploaded evidence artifacts are written to `backend/storage/` with UUID prefixes and 64KB chunk streaming.
2. **Four Definitive Forensic Statuses**:
   - `VERIFIED` (Green): Computed file hash matches the registered acquisition reference hash.
   - `MISMATCH` (Red): Disk hash differs from reference hash (flags tampering, corruption, or provenance breach).
   - `UNVERIFIED` (Amber): Ingested artifact has a valid hash, but no reference has yet been registered. A hash calculated after upload is not proof of original authenticity.
   - `ERROR` (Red): Evidence record exists in the database, but file is missing or unreadable on disk.
3. **Immutable Audit Hash-Chaining**:
   ```
   record_hash = SHA-256(event_id | evidence_id | event_type | timestamp | actor_id | details | verification_result | previous_hash)
   ```

---

## ⚖️ Regulatory Reference: 49 CFR Part 563

Title 49 Code of Federal Regulations Part 563 establishes federal requirements for light-duty vehicle Event Data Recorders:
- **Table 1 Data Elements (Mandatory)**: Pre-crash vehicle speed (-5.0s to 0.0s @ 2 Hz), Engine throttle % (-5.0s to 0.0s @ 2 Hz), Service brake status (ON/OFF @ 2 Hz), Longitudinal delta-V (0 - 250 ms @ 100 Hz), Driver seatbelt status (latched/unlatched), Frontal air bag deployment time.
- **Table 2 Data Elements (Equipped Vehicles)**: Steering wheel angle (-5.0s to 0.0s @ 2 Hz), Yaw rate (-5.0s to 0.0s @ 2 Hz), Lateral acceleration, ABS activity, Stability control.

*Notice*: 49 CFR Part 563 is a federal regulation, not a software library. Full legal admissibility requires physical chain of custody, hardware tool calibration records (e.g. Bosch CDR), and accredited forensic engineering testimony.

---

## 📊 Core API Endpoints

| Category | Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **System** | `GET` | `/api/health` | Diagnostic status of MySQL, storage, and PyTorch ML engine |
| **Cases** | `GET` | `/api/cases` | Lists all forensic investigations and vehicle metadata |
| **Cases** | `GET` | `/api/cases/{caseId}` | Retrieves specific case details and location information |
| **Evidence** | `POST` | `/api/evidence` | Ingests forensic artifact, computes SHA-256, writes to disk |
| **Evidence** | `GET` | `/api/cases/{caseId}/evidence` | Lists all evidence artifacts for a case |
| **Evidence** | `POST` | `/api/evidence/{id}/reference` | Binds trusted acquisition reference hash |
| **Evidence** | `POST` | `/api/evidence/{id}/verify` | Recalculates disk hash and updates verification verdict |
| **Evidence** | `GET` | `/api/evidence/{id}/history` | Retrieves hash-chained chain-of-custody audit trail |
| **EDR / Telemetry** | `GET` | `/api/cases/{caseId}/edr` | Returns 49 CFR Part 563 Table 1 & Table 2 pre-crash data points |
| **Telemetry** | `POST` | `/api/telemetry/ingest` | Ingests and normalizes raw CAN bus or EDR binary data |
| **Reconstruction** | `GET` | `/api/cases/{caseId}/reconstruction/topdown` | Returns continuous kinematic trajectory coordinates |
| **Reconstruction** | `GET` | `/api/cases/{caseId}/timeline` | Synchronized chronological event sequence |
| **Simulation** | `POST` | `/api/cases/{caseId}/simulation/what-if` | Counterfactual physics: stopping distance vs network latency |
| **Machine Learning**| `POST` | `/api/ml/predict-severity` | PyTorch neural network crash severity inference + XAI weights |
| **Machine Learning**| `GET` | `/api/ml/models` | Lists validated ML models and evaluation metrics in MySQL |
| **Anomalies** | `GET` | `/api/cases/{caseId}/anomalies` | Explainable anomaly findings with baselines and confidence |
| **Correlations** | `GET` | `/api/cases/{caseId}/correlations` | Multi-sensor cross-validation (CAN, EDR, Radar, Camera) |
| **Reports** | `GET` | `/api/cases/{caseId}/report` | Compiles comprehensive, defensible forensic report |
| **Regulatory** | `GET` | `/api/regulatory/49cfr563` | 49 CFR Part 563 regulatory reference documentation |
