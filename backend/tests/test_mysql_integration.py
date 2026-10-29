import os
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend import config
from backend.database import (
    Base,
    EvidenceModel,
    AuditLogModel,
    init_db,
    log_audit_event,
    compute_record_hash
)

def get_mysql_test_url() -> str:
    """Read MySQL test connection URL from environment or construct from settings."""
    explicit_url = os.getenv("TEST_MYSQL_URL")
    if explicit_url:
        return explicit_url

    # Check if standard config is pointing to a MySQL instance
    if config.DATABASE_URL.startswith("mysql"):
        return config.DATABASE_URL

    return config.build_database_url()

def is_mysql_reachable(url: str) -> bool:
    try:
        engine = create_engine(url, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False

MYSQL_URL = get_mysql_test_url()
CAN_CONNECT_MYSQL = is_mysql_reachable(MYSQL_URL)

@pytest.mark.skipif(
    not CAN_CONNECT_MYSQL,
    reason=f"Live MySQL database is not accessible at {config.get_database_url_safe(MYSQL_URL)}. Skipping live MySQL integration tests."
)
class TestLiveMySQLIntegration:
    @pytest.fixture(scope="class")
    def mysql_engine(self):
        engine = create_engine(MYSQL_URL, pool_pre_ping=True)
        Base.metadata.create_all(bind=engine)
        yield engine
        engine.dispose()

    def test_mysql_live_connection(self, mysql_engine):
        with mysql_engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            assert result == 1

    def test_mysql_evidence_crud_and_audit(self, mysql_engine):
        SessionFactory = sessionmaker(bind=mysql_engine)
        session = SessionFactory()

        test_ev_id = "ev-mysql-live-01"
        try:
            # Clean up if existing
            existing = session.get(EvidenceModel, test_ev_id)
            if existing:
                session.delete(existing)
                session.commit()

            ev = EvidenceModel(
                id=test_ev_id,
                case_id="CASE_MYSQL_01",
                filename="mysql_test.log",
                storage_filename="ev-mysql-live-01_mysql_test.log",
                file_size=512,
                mime_type="text/plain",
                evidence_type="CAN_BUS_DUMP",
                sha256="c" * 64,
                trusted_reference="c" * 64,
                status="VERIFIED",
                investigator_id="MySQL_Test_Runner"
            )
            session.add(ev)
            session.commit()

            # Add audit entry
            entry = log_audit_event(
                session=session,
                evidence_id=test_ev_id,
                event_type="INGESTION",
                actor_id="MySQL_Test_Runner",
                details="Live MySQL integration test record",
                verification_result="VERIFIED",
                commit=True
            )
            assert entry.id is not None
            assert entry.record_hash is not None

            # Verify fetch
            fetched = session.get(EvidenceModel, test_ev_id)
            assert fetched.filename == "mysql_test.log"
            assert fetched.status == "VERIFIED"
            assert len(fetched.audit_events) >= 1

        finally:
            # Clean up test row
            to_clean = session.get(EvidenceModel, test_ev_id)
            if to_clean:
                session.delete(to_clean)
                session.commit()
            session.close()
