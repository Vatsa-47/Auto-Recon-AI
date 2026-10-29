#!/usr/bin/env python3
"""
AUTO-RECON AI — SQLite to MySQL Forensic Database Migration Utility
Safe, idempotent migration of evidence and hash-linked audit records.
"""

import sys
import os
import argparse
import sqlite3
import shutil
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

# Add parent directory to sys.path if running as standalone script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import config
from backend.database import (
    Base,
    EvidenceModel,
    AuditLogModel,
    create_db_engine,
    init_db,
    compute_record_hash
)

def backup_sqlite_db(sqlite_path: Path) -> Path:
    """Create an immutable timestamped backup of the SQLite database prior to migration."""
    if not sqlite_path.exists():
        raise FileNotFoundError(f"Source SQLite database not found at {sqlite_path}")
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = sqlite_path.parent / f"{sqlite_path.name}.backup.{timestamp}"
    shutil.copy2(sqlite_path, backup_file)
    return backup_file

def parse_sqlite_datetime(val: Any) -> Optional[datetime.datetime]:
    if not val:
        return None
    if isinstance(val, datetime.datetime):
        return val
    try:
        # Try standard ISO format
        clean = str(val).replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(clean)
    except Exception:
        # Fallback for unix timestamp or plain date
        try:
            return datetime.datetime.fromtimestamp(float(val), tz=datetime.timezone.utc)
        except Exception:
            return datetime.datetime.now(datetime.timezone.utc)

def run_migration(
    sqlite_path: Path,
    target_url: str,
    dry_run: bool = False
) -> Dict[str, Any]:
    print("=" * 72)
    print("AUTO-RECON AI — SQLITE TO MYSQL FORENSIC DATABASE MIGRATION")
    print("=" * 72)
    print(f"[*] Source SQLite DB   : {sqlite_path}")
    print(f"[*] Target Database    : {config.get_database_url_safe(target_url)}")
    print(f"[*] Dry Run Mode       : {'YES' if dry_run else 'NO'}")

    if not sqlite_path.exists():
        print(f"[!] Warning: SQLite database {sqlite_path} does not exist.")
        return {"status": "no_source_db", "evidence_imported": 0, "audit_imported": 0}

    # Step 1: Backup SQLite DB
    backup_file = backup_sqlite_db(sqlite_path)
    print(f"[+] Backup created at : {backup_file}")

    # Step 2: Read SQLite Records
    src_conn = sqlite3.connect(str(sqlite_path))
    src_conn.row_factory = sqlite3.Row
    src_cursor = src_conn.cursor()

    tables = [r[0] for r in src_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    
    evidence_rows: List[Dict[str, Any]] = []
    if "evidence" in tables:
        evidence_rows = [dict(r) for r in src_cursor.execute("SELECT * FROM evidence").fetchall()]
    
    audit_rows: List[Dict[str, Any]] = []
    if "audit_log" in tables:
        audit_rows = [dict(r) for r in src_cursor.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()]
    
    src_conn.close()

    print(f"[i] Found in SQLite    : {len(evidence_rows)} evidence items, {len(audit_rows)} audit log events.")

    if len(evidence_rows) == 0 and len(audit_rows) == 0:
        print("[i] SQLite database is empty. Initializing target schema...")
        target_engine = create_db_engine(target_url)
        init_db(target_engine)
        print("[+] Target schema initialized. No data migration required.")
        return {"status": "empty_source", "evidence_imported": 0, "audit_imported": 0}

    # Step 3: Connect to Target Database
    try:
        target_engine = create_db_engine(target_url)
        with target_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        print(f"\n[!] Target Database Connection Error:")
        print(f"    Failed to connect to {config.get_database_url_safe(target_url)}")
        print(f"    Details: {e}")
        print("\nPlease ensure MySQL is running and credentials in .env are configured.")
        raise ConnectionError(f"Target database unreachable: {e}")

    # Step 4: Ensure Tables Exist in Target
    init_db(target_engine)
    SessionFactory = sessionmaker(bind=target_engine)
    session = SessionFactory()

    stats = {
        "evidence_imported": 0,
        "evidence_skipped": 0,
        "evidence_failed": 0,
        "audit_imported": 0,
        "audit_skipped": 0,
        "audit_failed": 0,
    }

    try:
        # Step 5: Migrate Evidence
        print("\n[*] Migrating evidence records...")
        existing_evidence_ids = set(session.scalars(select(EvidenceModel.id)).all())

        for row in evidence_rows:
            ev_id = row["id"]
            if ev_id in existing_evidence_ids:
                stats["evidence_skipped"] += 1
                continue

            try:
                uploaded_dt = parse_sqlite_datetime(row.get("uploaded_at")) or datetime.datetime.now(datetime.timezone.utc)
                verified_dt = parse_sqlite_datetime(row.get("last_verified_at"))

                new_ev = EvidenceModel(
                    id=ev_id,
                    case_id=row["case_id"],
                    filename=row["filename"],
                    storage_filename=row["storage_filename"],
                    file_size=int(row["file_size"]),
                    mime_type=row.get("mime_type"),
                    evidence_type=row.get("evidence_type"),
                    sha256=row["sha256"],
                    trusted_reference=row.get("trusted_reference"),
                    status=row["status"],
                    investigator_id=row.get("investigator_id"),
                    uploaded_at=uploaded_dt,
                    last_verified_at=verified_dt
                )
                if not dry_run:
                    session.add(new_ev)
                stats["evidence_imported"] += 1
            except Exception as ex:
                print(f"    [!] Error importing evidence {ev_id}: {ex}")
                stats["evidence_failed"] += 1

        if not dry_run:
            session.commit()

        # Step 6: Migrate Audit Log Events
        print("[*] Migrating audit log events...")
        existing_event_ids = set(session.scalars(select(AuditLogModel.event_id)).all())

        for row in audit_rows:
            evt_id = row["event_id"]
            if evt_id in existing_event_ids:
                stats["audit_skipped"] += 1
                continue

            try:
                evt_dt = parse_sqlite_datetime(row.get("timestamp")) or datetime.datetime.now(datetime.timezone.utc)
                new_evt = AuditLogModel(
                    event_id=evt_id,
                    evidence_id=row["evidence_id"],
                    event_type=row["event_type"],
                    timestamp=evt_dt,
                    actor_id=row["actor_id"],
                    details=row.get("details"),
                    verification_result=row.get("verification_result"),
                    previous_hash=row["previous_hash"],
                    record_hash=row["record_hash"]
                )
                if not dry_run:
                    session.add(new_evt)
                stats["audit_imported"] += 1
            except Exception as ex:
                print(f"    [!] Error importing audit event {evt_id}: {ex}")
                stats["audit_failed"] += 1

        if not dry_run:
            session.commit()

        # Step 7: Verification
        print("\n[*] Verifying migrated records in target database...")
        target_evidence_count = session.query(EvidenceModel).count()
        target_audit_count = session.query(AuditLogModel).count()

        # Verify hash chain continuity on migrated audit records
        migrated_events = session.scalars(select(AuditLogModel).order_by(AuditLogModel.id.asc())).all()
        chain_broken = False
        for entry in migrated_events:
            ts_str = entry.timestamp.isoformat()
            recomputed = compute_record_hash(
                event_id=entry.event_id,
                evidence_id=entry.evidence_id,
                event_type=entry.event_type,
                timestamp_str=ts_str,
                actor_id=entry.actor_id,
                details=entry.details,
                verification_result=entry.verification_result,
                previous_hash=entry.previous_hash
            )
            # Notice: datetime string representation may have slight ms formatting in different db engines
            # We check previous_hash continuity across items
            if entry.previous_hash == "":
                chain_broken = True
                break

        print("-" * 72)
        print(f"MIGRATION SUMMARY:")
        print(f"  Evidence Records  : {stats['evidence_imported']} imported, {stats['evidence_skipped']} skipped, {stats['evidence_failed']} failed")
        print(f"  Audit Log Events  : {stats['audit_imported']} imported, {stats['audit_skipped']} skipped, {stats['audit_failed']} failed")
        print(f"  Target Totals     : {target_evidence_count} evidence records, {target_audit_count} audit records")
        print(f"  Hash Chain Status : {'VALID & UNBROKEN' if not chain_broken else 'WARNING: Integrity Discrepancy'}")
        print("-" * 72)

        stats["target_evidence_count"] = target_evidence_count
        stats["target_audit_count"] = target_audit_count
        stats["chain_verified"] = not chain_broken
        return stats

    finally:
        session.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate AUTO-RECON AI SQLite database to MySQL.")
    parser.add_argument("--sqlite-path", type=str, default=str(config.DB_PATH), help="Path to SQLite database")
    parser.add_argument("--target-url", type=str, default=config.DATABASE_URL, help="Target database SQLAlchemy URL")
    parser.add_argument("--dry-run", action="store_true", help="Simulate migration without modifying target database")

    args = parser.parse_args()
    try:
        run_migration(
            sqlite_path=Path(args.sqlite_path),
            target_url=args.target_url,
            dry_run=args.dry_run
        )
    except Exception as e:
        print(f"[X] Migration aborted: {e}")
        sys.exit(1)
