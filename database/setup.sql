-- ====================================================================
-- AUTO-RECON AI — MySQL 8.0 Database Setup & Initialization Script
-- Exact Database Name: autorecon
--
-- How to run this script:
--   Option A (From PowerShell / Command Prompt as root):
--     & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p < database/setup.sql
--
--   Option B (Inside MySQL Command Line Client):
--     source database/setup.sql;
-- ====================================================================

-- 1. Create the database with UTF-8mb4 character set
CREATE DATABASE IF NOT EXISTS autorecon
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

-- 2. Create dedicated non-root application user
CREATE USER IF NOT EXISTS 'autorecon_app'@'localhost'
  IDENTIFIED BY 'autorecon_secure_password_2026';

CREATE USER IF NOT EXISTS 'autorecon_app'@'127.0.0.1'
  IDENTIFIED BY 'autorecon_secure_password_2026';

-- 3. Grant necessary application permissions on autorecon schema
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES
  ON autorecon.* TO 'autorecon_app'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES
  ON autorecon.* TO 'autorecon_app'@'127.0.0.1';

FLUSH PRIVILEGES;

-- 4. Switch to autorecon database
USE autorecon;

-- 5. Investigations & Cases Table
CREATE TABLE IF NOT EXISTS cases (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    short_title VARCHAR(255),
    scenario_type VARCHAR(128),
    incident_time VARCHAR(64),
    location_address VARCHAR(255),
    latitude DOUBLE,
    longitude DOUBLE,
    speed_limit DOUBLE,
    road_condition VARCHAR(128),
    summary TEXT,
    summary_tags TEXT,
    primary_data_sources TEXT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_case_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Vehicles Table
CREATE TABLE IF NOT EXISTS vehicles (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL,
    make VARCHAR(64) NOT NULL,
    model VARCHAR(64) NOT NULL,
    year INT NOT NULL,
    vin VARCHAR(64) NOT NULL,
    ecu_firmware VARCHAR(64),
    edr_module VARCHAR(64),
    role VARCHAR(64) DEFAULT 'Subject Vehicle',
    color VARCHAR(32),
    INDEX idx_vehicle_case (case_id),
    CONSTRAINT fk_vehicle_case FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Evidence Table
CREATE TABLE IF NOT EXISTS evidence (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    storage_filename VARCHAR(255) NOT NULL UNIQUE,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(128),
    evidence_type VARCHAR(64),
    sha256 VARCHAR(64) NOT NULL,
    trusted_reference VARCHAR(64),
    status VARCHAR(32) NOT NULL,
    investigator_id VARCHAR(128),
    uploaded_at DATETIME(6) NOT NULL,
    last_verified_at DATETIME(6),
    INDEX idx_evidence_case (case_id),
    INDEX idx_evidence_sha256 (sha256),
    INDEX idx_evidence_uploaded (uploaded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Audit Log Table (FIPS 180-4 SHA-256 Hash Chain of Custody)
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    evidence_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    timestamp DATETIME(6) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    details TEXT,
    verification_result VARCHAR(32),
    previous_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL,
    INDEX idx_audit_evidence (evidence_id),
    INDEX idx_audit_time (timestamp),
    CONSTRAINT fk_audit_evidence FOREIGN KEY (evidence_id) REFERENCES evidence (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. Timeline Events (49 CFR Part 563 Synchronized Events)
CREATE TABLE IF NOT EXISTS timeline_events (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL,
    time_offset_s DOUBLE NOT NULL,
    event_name VARCHAR(128) NOT NULL,
    source VARCHAR(64) NOT NULL,
    description TEXT,
    speed_kph DOUBLE,
    brake_status VARCHAR(32),
    throttle_pct DOUBLE,
    steering_deg DOUBLE,
    delta_v_kph DOUBLE,
    is_critical BOOLEAN DEFAULT FALSE,
    uncertainty_ms INT DEFAULT 20,
    INDEX idx_timeline_case (case_id),
    INDEX idx_timeline_time (time_offset_s)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. Explainable Anomaly Findings
CREATE TABLE IF NOT EXISTS anomalies (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL,
    time_rel VARCHAR(32) NOT NULL,
    component VARCHAR(128) NOT NULL,
    parameter VARCHAR(128) NOT NULL,
    observed_value VARCHAR(128) NOT NULL,
    baseline_threshold VARCHAR(128) NOT NULL,
    explanation TEXT NOT NULL,
    supporting_evidence VARCHAR(255),
    confidence DOUBLE NOT NULL,
    severity VARCHAR(32) DEFAULT 'HIGH',
    limitations TEXT,
    INDEX idx_anomaly_case (case_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 11. Multi-Modal Evidence Correlations
CREATE TABLE IF NOT EXISTS correlations (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL,
    primary_source VARCHAR(128) NOT NULL,
    secondary_source VARCHAR(128) NOT NULL,
    correlation_type VARCHAR(64) NOT NULL,
    confidence DOUBLE NOT NULL,
    time_delta_ms INT NOT NULL,
    finding TEXT NOT NULL,
    status VARCHAR(32) DEFAULT 'CORRELATED',
    INDEX idx_correlation_case (case_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 12. ML Models & Historical Evaluation Records
CREATE TABLE IF NOT EXISTS ml_models (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    version VARCHAR(32) NOT NULL,
    framework VARCHAR(64) NOT NULL,
    task VARCHAR(128) NOT NULL,
    dataset_name VARCHAR(128) NOT NULL,
    accuracy DOUBLE,
    f1_score DOUBLE,
    loss DOUBLE,
    model_path VARCHAR(255),
    trained_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    metadata_json TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 13. Forensic Reports Table
CREATE TABLE IF NOT EXISTS forensic_reports (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL,
    report_number VARCHAR(64) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    generated_at DATETIME(6) NOT NULL,
    author_id VARCHAR(128) NOT NULL,
    regulatory_reference VARCHAR(128) DEFAULT '49 CFR Part 563 & ISO 26021',
    content_json MEDIUMTEXT NOT NULL,
    INDEX idx_report_case (case_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
