# AUTO-RECON AI: AI-Driven Incident Reconstruction for Automotive Digital Forensics

> **Automotive Digital Forensics & Cryptographic Evidence Verification Platform (MySQL 8.0 & SQLAlchemy 2.x)**

![Forensics](https://img.shields.io/badge/Forensics-Automotive%20Black%20Box-2563eb?style=for-the-badge)
![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.12%20%7C%20MySQL%208.0-059669?style=for-the-badge)
![ORM](https://img.shields.io/badge/Database-SQLAlchemy%202.x%20%7C%20PyMySQL-0284c7?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-FIPS%20180--4%20SHA--256%20%7C%20Hash--Chaining-7c3aed?style=for-the-badge)
![Compliance](https://img.shields.io/badge/Compliance-ISO%2026021%20%7C%2049%20CFR%20Part%20563-10b981?style=for-the-badge)

---

## 📌 Problem Statement

> *"Current automotive forensic investigations are fragmented across proprietary tools and heterogeneous evidence sources (EDR, CAN bus, ECU diagnostics, camera HUD, and telemetry). AUTO-RECON AI correlates these digital sources into an explainable, physics-grounded incident reconstruction with a legally defensible cryptographic chain-of-custody ledger backed by an enterprise MySQL database."*

---

## 🏗️ MySQL Database Setup & Configuration

### 1. Prerequisites
- **MySQL Server 8.0+** running locally or accessible via network.
- **Python 3.10+** (tested on Python 3.12).
- Modern web browser (Chrome, Edge, Firefox).

---

### 2. Database & Non-Root Application User Setup

For digital forensic security and Principle of Least Privilege, do **not** use the MySQL `root` account for normal application execution. Create a dedicated application user with restricted schema privileges.

#### Automated SQL Setup:
Run the provided SQL script using the MySQL client:
```bash
mysql -u root -p < backend/setup_mysql.sql
```

#### Or Run Manually in MySQL Shell (`mysql -u root -p`):
```sql
-- 1. Create the database
CREATE DATABASE IF NOT EXISTS autorecon_ai 
  CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

-- 2. Create the dedicated non-root application user
CREATE USER IF NOT EXISTS 'autorecon_app'@'localhost' IDENTIFIED BY 'CHANGE_ME_SECURE_PASSWORD';
CREATE USER IF NOT EXISTS 'autorecon_app'@'127.0.0.1' IDENTIFIED BY 'CHANGE_ME_SECURE_PASSWORD';

-- 3. Grant only required privileges on the forensic schema
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER, REFERENCES 
  ON autorecon_ai.* TO 'autorecon_app'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER, REFERENCES 
  ON autorecon_ai.* TO 'autorecon_app'@'127.0.0.1';

-- 4. Apply changes
FLUSH PRIVILEGES;
```

---

### 3. Environment Variable Configuration (`.env`)

Copy `.env.example` to `.env` in the project root:
```bash
cp .env.example .env
```

Edit `.env` to match your MySQL credentials:
```ini
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=autorecon_ai
DB_USER=autorecon_app
DB_PASSWORD=CHANGE_ME_SECURE_PASSWORD

# Optional Full Connection URL (takes precedence if provided)
# DATABASE_URL=mysql+pymysql://autorecon_app:CHANGE_ME_SECURE_PASSWORD@127.0.0.1:3306/autorecon_ai?charset=utf8mb4

# Pool Settings
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_RECYCLE=1800

# Storage
AUTORECON_STORAGE_DIR=backend/storage
```

---

### 4. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

---

### 5. Idempotent SQLite to MySQL Data Migration

To safely transfer existing records from `autorecon.db` into MySQL without losing any evidence IDs, hashes, or audit trail continuity:

```bash
# Dry-run test (simulates migration without writing to MySQL):
python backend/migrate_sqlite_to_mysql.py --dry-run

# Execute full migration:
python backend/migrate_sqlite_to_mysql.py
```

#### Migration Guarantees:
- **Pre-Migration Backup**: Automatically creates an immutable timestamped backup (e.g. `autorecon.db.backup.20261015_205615`).
- **Original DB Intact**: Does not delete or alter the original SQLite database.
- **Idempotent**: Re-running the migration skips already imported records without duplicating keys or breaking foreign key links.
- **Verification**: Validates record counts, foreign key integrity, and cryptographic hash chain continuity upon completion.

---

### 6. Launch the Application

#### Start the FastAPI Backend Engine:
```bash
uvicorn backend.main:app --reload --port 8000
```
- API Base: `http://127.0.0.1:8000`
- Interactive API Docs (Swagger): `http://127.0.0.1:8000/docs`
- Health Endpoint: `http://127.0.0.1:8000/api/health`

#### Open the Forensic Dashboard:
```bash
# Direct Open
start index.html

# Or via local static server
python -m http.server 5500
# Navigate to http://localhost:5500
```

---

## 🔐 Cryptographic Evidence Verification & Chain of Custody

The Evidence Ledger implements tamper-evident digital forensic integrity:

1. **Streaming SHA-256 Hashing**: 
   Files uploaded via `POST /api/evidence` are saved to `backend/storage/` with UUID-prefixed sanitization to prevent path traversal and overwrites. Hashes are computed via 64KB chunk streaming.
2. **Defensible Verification Statuses**:
   - `VERIFIED` (Green): Recalculated disk SHA-256 matches the trusted acquisition reference hash.
   - `MISMATCH` (Red): Disk SHA-256 differs from the reference hash (indicates file tampering, corruption, or provenance breach).
   - `UNVERIFIED` (Amber): Ingested artifact has a valid computed hash, but no reference hash has yet been registered from the acquisition property sheet.
   - `ERROR` (Red): Artifact record exists in the ledger, but the underlying file on disk is missing or unreadable.
3. **Hash-Chained Audit Trail**:
   Every lifecycle event (`INGESTION`, `REFERENCE_ADDED`, `INTEGRITY_VERIFICATION`) appends an immutable block linked to the previous block's hash:
   $$\text{record\_hash} = \text{SHA-256}(\text{event\_id} + \text{evidence\_id} + \text{event\_type} + \text{timestamp} + \text{actor\_id} + \text{details} + \text{previous\_hash})$$

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health status of backend engine, MySQL connection, and forensic storage |
| `POST` | `/api/evidence` | Ingests forensic artifact (multipart: `file`, `case_id`, `evidence_type`, `trusted_reference`) |
| `GET` | `/api/evidence` | Lists all evidence artifacts (filter by `?case_id=...`) |
| `GET` | `/api/evidence/{id}` | Retrieves metadata and verification status of a specific artifact |
| `POST` | `/api/evidence/{id}/reference` | Registers a 64-character trusted reference hash and re-verifies |
| `POST` | `/api/evidence/{id}/verify` | Re-reads physical file from disk, recalculates SHA-256, and logs audit record |
| `POST` | `/api/evidence/verify-all` | Batch recalculates disk integrity for all evidence artifacts in a case |
| `GET` | `/api/evidence/{id}/history` | Retrieves the hash-chained audit log and validates cryptographic chain continuity |
| `GET` | `/api/cases/{case_id}/evidence` | Fetches evidence files linked to a given case |

---

## 🧪 Automated Testing

Run the automated pytest test suite:

```bash
python -m pytest backend/tests/ -v
```

### Test Suite Coverage:
- **11 Preserved Core Tests**: Ingestion, unverified by default, matching hash, mismatch detection, dynamic reference assignment, physical disk tamper detection, missing file error handling, hash chain validation, regex validation, case filtering, and 404 responses.
- **5 Migration & Resilience Tests**:
  - `test_persistent_evidence_and_audit_across_reconnect`: Validates record persistence across new database sessions.
  - `test_transaction_rollback_on_failure`: Confirms transactions roll back atomically on database errors.
  - `test_database_configuration_url_helper_and_masking`: Verifies URL generation and password masking in logs.
  - `test_unavailable_database_server_reports_degraded_and_503`: Verifies that if MySQL is unreachable, `/api/health` reports degraded and endpoints return HTTP 503 instead of falling back to SQLite.
  - `test_idempotent_sqlite_to_sql_migration`: Validates two-pass migration idempotency, zero duplicate records, and unbroken hash-chaining.
- **2 Live MySQL Integration Tests**:
  - `test_mysql_live_connection`: Tests live query execution on running MySQL instance when credentials are configured.
  - `test_mysql_evidence_crud_and_audit`: Live table creation, evidence ingestion, audit chaining, and teardown.
  - *Note*: Gracefully skipped when local MySQL credentials have not been configured yet.

---

## 🚗 Demonstration Incident Scenarios

1. **Case AF-8902**: *1. Urban Intersection — Brake Response Anomaly*
2. **Case AF-4421**: *2. Highway Exit — Sudden Acceleration Analysis*
3. **Case AF-6715**: *3. ADAS Handover — Late Driver Warning*
4. **Case AF-9104**: *4. Steering System — Sensor Anomaly*
5. **Case AF-3389**: *5. Heavy Vehicle — Brake Pressure Loss*
6. **Case AF-1082**: *6. Pedestrian AEB — Sensor Conflict*
7. **Case AF-2041**: *7. Severe Data Loss / Truncated Buffer*

---

## 👥 Authors
- **Srivatsa M.**
- **Chandra Shekar Rao P.**
- **Kanishka Mishra**
