-- ====================================================================
-- AUTO-RECON AI — MySQL Inspection Queries for MySQL Command Line Client
-- Run inside MySQL client:
--   USE auto_recon;
--   source C:/Users/sriva/OneDrive/Desktop/Auto Recon AI Old Version/database/inspect_evidence.sql;
-- Or from PowerShell:
--   & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u autorecon_app -p -e "source database/inspect_evidence.sql"
-- ====================================================================

USE auto_recon;

SELECT '===================================================' AS '';
SELECT '1. ALL EVIDENCE ARTIFACTS & STATUSES' AS 'QUERY REPORT';
SELECT '===================================================' AS '';
SELECT 
    id AS 'Evidence ID',
    case_id AS 'Case ID',
    filename AS 'Artifact Filename',
    ROUND(file_size / 1024, 2) AS 'Size (KB)',
    status AS 'Verification Status',
    investigator_id AS 'Investigator',
    uploaded_at AS 'Uploaded At (UTC)'
FROM evidence
ORDER BY uploaded_at DESC;

SELECT '===================================================' AS '';
SELECT '2. CRYPTOGRAPHIC HASHES & REFERENCE ALIGNMENT' AS 'QUERY REPORT';
SELECT '===================================================' AS '';
SELECT 
    id AS 'Evidence ID',
    filename AS 'Filename',
    sha256 AS 'Disk Computed SHA-256',
    IFNULL(trusted_reference, '[NONE CONFIGURED]') AS 'Trusted Reference Hash',
    status AS 'Integrity Status',
    last_verified_at AS 'Last Verified At'
FROM evidence
ORDER BY uploaded_at DESC;

SELECT '===================================================' AS '';
SELECT '3. EVIDENCE SUMMARY BY CASE' AS 'QUERY REPORT';
SELECT '===================================================' AS '';
SELECT 
    case_id AS 'Case ID',
    COUNT(*) AS 'Total Artifacts',
    SUM(CASE WHEN status = 'VERIFIED' THEN 1 ELSE 0 END) AS 'Verified Count',
    SUM(CASE WHEN status = 'MISMATCH' THEN 1 ELSE 0 END) AS 'Mismatch Count',
    SUM(CASE WHEN status = 'UNVERIFIED' THEN 1 ELSE 0 END) AS 'Unverified Count',
    SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) AS 'Storage Error Count'
FROM evidence
GROUP BY case_id
ORDER BY case_id ASC;

SELECT '===================================================' AS '';
SELECT '4. CHAIN-OF-CUSTODY AUDIT LOGS (HASH CHAIN)' AS 'QUERY REPORT';
SELECT '===================================================' AS '';
SELECT 
    id AS 'Log ID',
    evidence_id AS 'Evidence ID',
    event_type AS 'Event Type',
    actor_id AS 'Actor',
    verification_result AS 'Result',
    LEFT(previous_hash, 16) AS 'Prev Hash (Trunc)',
    LEFT(record_hash, 16) AS 'Record Hash (Trunc)',
    timestamp AS 'Timestamp (UTC)'
FROM audit_log
ORDER BY id ASC;

SELECT '===================================================' AS '';
SELECT '5. VERIFICATION HISTORY SPECIFICALLY' AS 'QUERY REPORT';
SELECT '===================================================' AS '';
SELECT 
    a.id AS 'Log ID',
    a.evidence_id AS 'Evidence ID',
    e.filename AS 'Filename',
    a.actor_id AS 'Verified By',
    a.verification_result AS 'Verification Outcome',
    a.details AS 'Verification Details',
    a.timestamp AS 'Timestamp'
FROM audit_log a
JOIN evidence e ON a.evidence_id = e.id
WHERE a.event_type = 'INTEGRITY_VERIFICATION'
ORDER BY a.id DESC;
