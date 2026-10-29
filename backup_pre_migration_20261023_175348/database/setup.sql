-- ====================================================================
-- AUTO-RECON AI — MySQL Database Setup & Initialization Script
-- Database Name: auto_recon
--
-- How to run this script:
--   Option A (From PowerShell / Command Prompt):
--     & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p < database/setup.sql
--
--   Option B (Inside MySQL Command Line Client):
--     source C:/Users/sriva/OneDrive/Desktop/Auto Recon AI Old Version/database/setup.sql;
-- ====================================================================

-- 1. Create the database with UTF-8mb4 character set
CREATE DATABASE IF NOT EXISTS auto_recon
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

-- 2. Create dedicated non-root application user
CREATE USER IF NOT EXISTS 'autorecon_app'@'localhost'
  IDENTIFIED BY 'autorecon_secure_password_2026';

CREATE USER IF NOT EXISTS 'autorecon_app'@'127.0.0.1'
  IDENTIFIED BY 'autorecon_secure_password_2026';

-- 3. Grant necessary application permissions on auto_recon schema
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES
  ON auto_recon.* TO 'autorecon_app'@'localhost';

GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, REFERENCES
  ON auto_recon.* TO 'autorecon_app'@'127.0.0.1';

FLUSH PRIVILEGES;

-- 4. Switch to auto_recon database
USE auto_recon;

-- 5. Create evidence table
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

-- 6. Create audit_log table
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
    INDEX idx_audit_event (event_id),
    INDEX idx_audit_evidence (evidence_id),
    INDEX idx_audit_timestamp (timestamp),
    INDEX idx_audit_evidence_time (evidence_id, timestamp),
    CONSTRAINT fk_audit_evidence FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Verification output
SHOW TABLES;
