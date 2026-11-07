"""
Test Suite: TiDB Cloud & Render Free Deployment Security Configurations
Covers:
  - Database password requirement (no hardcoded fallback)
  - URL-based TiDB Cloud detection (inspecting create_db_engine target URL directly)
  - Mandatory TLS and hostname verification for TiDB Cloud
  - Startup error when CA certificate is missing (via URL or environment)
  - Strict Base64 CA certificate decoding and validation (rejecting corrupt Base64)
  - Python SSL X.509 PEM certificate structure validation (valid vs invalid PEM)
  - Authentic TiDB CA Certificate fixture verified by SHA256 checksum
  - PyMySQL connect_args with ssl, check_hostname, and verify_mode == ssl.CERT_REQUIRED
  - PyMySQL ssl_verify_cert=True and ssl_verify_identity=True passed to connection
  - Explicit CORS policy rejecting '*' and 'null', ensuring Vercel frontend in production
  - Requirement of DB_USER for TiDB Cloud (no assumption of 'autorecon_app')
  - Render Free connection pool configuration (pool_size=5, pool_recycle=300)
"""

import os
import ssl
import base64
import hashlib
from pathlib import Path
from unittest.mock import patch
import pytest
import pymysql.connections

from backend import config
from backend.database import create_db_engine

# ====================================================================
# AUTHENTIC TIDB CLOUD CA CERTIFICATE FIXTURE
# Verified against the official TiDB Cloud CA Certificate (ISRG Root X1 authority)
# Expected SHA-256 Checksum: 22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1
# ====================================================================
EXPECTED_TIDB_CA_SHA256 = "22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1"

# Check if the user's local TiDB CA file is available
LOCAL_TIDB_CA_PATH = Path(r"C:\Users\sriva\Downloads\CA Certificate TIDb.pem")
if LOCAL_TIDB_CA_PATH.exists():
    AUTHENTIC_TIDB_CA_PEM = LOCAL_TIDB_CA_PATH.read_text(encoding="utf-8")
else:
    AUTHENTIC_TIDB_CA_PEM = (
        "-----BEGIN CERTIFICATE-----\n"
        "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\n"
        "-----END CERTIFICATE-----\n"
    )

AUTHENTIC_TIDB_CA_B64 = base64.b64encode(AUTHENTIC_TIDB_CA_PEM.encode("utf-8")).decode("utf-8")


def test_missing_password_raises_startup_error():
    """Verify that omitting DB_PASSWORD raises a clear startup error (no hardcoded fallback)."""
    with patch.dict(os.environ, {"DB_PASSWORD": ""}, clear=False):
        with pytest.raises(ValueError) as excinfo:
            config.build_database_url(user="test_user", password="", host="127.0.0.1", port=3306, name="autorecon")
        assert "CRITICAL STARTUP ERROR" in str(excinfo.value)
        assert "DB_PASSWORD" in str(excinfo.value)


def test_url_based_tidb_detection():
    """
    Verify TiDB Cloud detection from the parsed URL passed to is_tidb_cloud()
    even when DB_HOST is set to localhost.
    """
    tidb_url = "mysql+pymysql://testuser:secret@gateway01.us-east-1.prod.aws.tidbcloud.com:4000/autorecon"
    local_url = "mysql+pymysql://testuser:secret@127.0.0.1:3306/autorecon"

    # Even if DB_HOST is localhost, URL targeting TiDB Cloud is detected
    with patch.object(config, "DB_HOST", "127.0.0.1"):
        assert config.is_tidb_cloud(tidb_url) is True
        assert config.is_tidb_cloud(local_url) is False

    # Standard environment host detection
    with patch.object(config, "DB_HOST", "gateway01.us-east-1.prod.aws.tidbcloud.com"):
        assert config.is_tidb_cloud() is True


def test_missing_ca_when_connecting_via_url():
    """
    Verify that passing a TiDB Cloud URL to create_db_engine() without a configured CA
    raises a startup error, preventing unverified TLS connections.
    """
    tidb_url = "mysql+pymysql://user:pass@gateway01.us-east-1.prod.aws.tidbcloud.com:4000/autorecon"
    with patch.dict(os.environ, {
        "DB_HOST": "127.0.0.1",
        "TIDB_CA_CERT_BASE64": "",
        "TIDB_CA_CERT_PATH": "",
        "DB_SSL_CA": ""
    }):
        config._decoded_ca_cert_path = None
        with pytest.raises(ValueError) as excinfo:
            create_db_engine(tidb_url)
        assert "CRITICAL STARTUP ERROR" in str(excinfo.value)
        assert "TIDB_CA_CERT_BASE64" in str(excinfo.value)


def test_corrupted_base64_ca_cert_raises_error():
    """Verify that a corrupted Base64 CA string is rejected during strict Base64 validation."""
    with patch.dict(os.environ, {"TIDB_CA_CERT_BASE64": "!not@valid#base64$"}):
        config._decoded_ca_cert_path = None
        with pytest.raises(ValueError) as excinfo:
            config.get_ca_cert_path()
        assert "CRITICAL STARTUP ERROR" in str(excinfo.value)
        assert "Invalid CA certificate in TIDB_CA_CERT_BASE64" in str(excinfo.value)


def test_valid_vs_invalid_pem_structures():
    """
    Verify X.509 PEM certificate structure validation using Python's SSL facilities:
    - Valid PEM succeeds
    - Empty content fails
    - Corrupted PEM headers fail
    - Corrupted ASN.1 certificate body fails
    """
    # 1. Valid PEM
    config.validate_ca_cert_pem(AUTHENTIC_TIDB_CA_PEM.encode("utf-8"))

    # 2. Empty PEM
    with pytest.raises(ValueError) as exc1:
        config.validate_ca_cert_pem(b"")
    assert "empty" in str(exc1.value).lower()

    # 3. Missing PEM headers
    with pytest.raises(ValueError) as exc2:
        config.validate_ca_cert_pem(b"some random text without headers")
    assert "PEM header/footer" in str(exc2.value)

    # 4. Corrupted ASN.1 body within headers
    corrupted_pem = "-----BEGIN CERTIFICATE-----\nInvalidBase64Content==\n-----END CERTIFICATE-----"
    with pytest.raises(ValueError) as exc3:
        config.validate_ca_cert_pem(corrupted_pem.encode("utf-8"))
    assert "Failed to parse X.509 CA certificate" in str(exc3.value)


def test_db_user_required_for_tidb_cloud():
    """
    Verify that targeting TiDB Cloud does NOT assume 'autorecon_app' as default DB_USER,
    and requires DB_USER explicitly matching TiDB Cloud's username format.
    """
    with patch.dict(os.environ, {
        "DB_HOST": "gateway01.us-east-1.prod.aws.tidbcloud.com",
        "DB_USER": "",
        "DB_PASSWORD": "secret_password",
        "TIDB_CA_CERT_BASE64": AUTHENTIC_TIDB_CA_B64
    }):
        with patch.object(config, "DB_HOST", "gateway01.us-east-1.prod.aws.tidbcloud.com"):
            with patch.object(config, "DB_USER", None):
                config._decoded_ca_cert_path = None
                with pytest.raises(ValueError) as excinfo:
                    config.build_database_url(user=None, password="secret_password")
                assert "DB_USER" in str(excinfo.value)
                assert "required for TiDB Cloud" in str(excinfo.value)

    # Providing actual TiDB username succeeds
    with patch.dict(os.environ, {
        "DB_HOST": "gateway01.us-east-1.prod.aws.tidbcloud.com",
        "DB_PASSWORD": "secret_password",
        "TIDB_CA_CERT_BASE64": AUTHENTIC_TIDB_CA_B64
    }):
        with patch.object(config, "DB_HOST", "gateway01.us-east-1.prod.aws.tidbcloud.com"):
            config._decoded_ca_cert_path = None
            url = config.build_database_url(user="2ABCxyz.root", password="secret_password")
            assert "2ABCxyz.root" in url


def test_explicit_cors_policy_rejecting_wildcard_and_null():
    """
    Verify that:
    1. Wildcard '*' and 'null' origins are strictly rejected.
    2. In production, localhost origins are not included by default.
    3. Production frontend 'https://auto-recon-ai-frontend.vercel.app' is always present.
    """
    # 1. Custom env var containing '*' and 'null'
    with patch.dict(os.environ, {"CORS_ORIGINS": "https://custom.app, *, null, 'null', \"*\", https://partner.app"}):
        origins = config.parse_cors_origins()
        assert "*" not in origins
        assert "null" not in origins
        assert "'null'" not in origins
        assert '"null"' not in origins
        assert "https://custom.app" in origins
        assert "https://partner.app" in origins
        assert "https://auto-recon-ai-frontend.vercel.app" in origins

    # 2. Production environment defaults (explicit, no localhost fallback)
    with patch.dict(os.environ, {"RENDER": "true", "CORS_ORIGINS": ""}):
        prod_origins = config.parse_cors_origins()
        assert prod_origins == ["https://auto-recon-ai-frontend.vercel.app"]
        assert "http://localhost:8000" not in prod_origins


def test_verified_tls_configuration_with_authentic_ca():
    """
    Verify create_db_engine configures PyMySQL with mandatory TLS certificate and hostname check:
    1. CA certificate matches authentic TiDB Cloud root SHA256 checksum.
    2. verify_mode == ssl.CERT_REQUIRED
    3. check_hostname is True
    4. ssl_verify_cert=True and ssl_verify_identity=True passed in connect_args
    5. PyMySQL SSLContext parses and loads the authentic TiDB CA certificate.
    6. Render Free connection pool settings (size=5, recycle=300).
    """
    # Verify the authentic CA PEM matches the expected official SHA256 fingerprint
    cert_sha256 = hashlib.sha256(AUTHENTIC_TIDB_CA_PEM.encode("utf-8")).hexdigest()
    assert cert_sha256 == EXPECTED_TIDB_CA_SHA256, (
        f"Authentic CA fixture SHA256 {cert_sha256} does not match expected {EXPECTED_TIDB_CA_SHA256}"
    )

    with patch.dict(os.environ, {
        "DB_HOST": "gateway01.us-east-1.prod.aws.tidbcloud.com",
        "TIDB_CA_CERT_BASE64": AUTHENTIC_TIDB_CA_B64
    }):
        with patch.object(config, "DB_HOST", "gateway01.us-east-1.prod.aws.tidbcloud.com"):
            config._decoded_ca_cert_path = None
            engine = create_db_engine("mysql+pymysql://user:pass@gateway01.us-east-1.prod.aws.tidbcloud.com:4000/autorecon")

            # Inspect engine connect_args from pool creator closure
            cargs = next(c.cell_contents for c in engine.pool._creator.__closure__ if hasattr(c.cell_contents, 'get'))

            # 1. Assert ssl configuration dictionary
            assert "ssl" in cargs
            assert cargs["ssl"]["verify_mode"] == ssl.CERT_REQUIRED
            assert cargs["ssl"]["check_hostname"] is True
            assert Path(cargs["ssl"]["ca"]).exists()

            # 2. Confirm PyMySQL's ssl_verify_cert=True and ssl_verify_identity=True are passed correctly
            assert cargs["ssl_verify_cert"] is True
            assert cargs["ssl_verify_identity"] is True

            # 3. Confirm the CA certificate is genuinely used by the PyMySQL SSL context
            dummy_conn = pymysql.connections.Connection.__new__(pymysql.connections.Connection)
            ctx = dummy_conn._create_ssl_ctx(cargs["ssl"])

            assert ctx.verify_mode == ssl.CERT_REQUIRED
            assert ctx.check_hostname is True

            # Verify CA certificate was genuinely parsed and loaded into the context
            loaded_ca_certs = ctx.get_ca_certs()
            assert len(loaded_ca_certs) >= 1
            ca_subject_dict = dict(x[0] for x in loaded_ca_certs[0]["subject"])
            assert ca_subject_dict.get("commonName") == "ISRG Root X1"
            assert ca_subject_dict.get("organizationName") == "Internet Security Research Group"

            # 4. Connection pool settings for Render Free
            assert engine.pool.size() == config.DB_POOL_SIZE
            assert engine.pool._recycle == config.DB_POOL_RECYCLE


def test_remote_host_tls_enforced_without_silent_downgrade():
    """
    Verify that when connecting to any non-localhost remote database with a CA certificate configured,
    TLS certificate and hostname verification are strictly enforced without silent downgrade.
    """
    remote_url = "mysql+pymysql://user:pass@remote-mysql.internal:3306/autorecon"
    with patch.dict(os.environ, {"TIDB_CA_CERT_BASE64": AUTHENTIC_TIDB_CA_B64}):
        config._decoded_ca_cert_path = None
        engine = create_db_engine(remote_url)
        cargs = next(c.cell_contents for c in engine.pool._creator.__closure__ if hasattr(c.cell_contents, 'get'))

        assert "ssl" in cargs
        assert cargs["ssl"]["verify_mode"] == ssl.CERT_REQUIRED
        assert cargs["ssl"]["check_hostname"] is True
        assert cargs["ssl_verify_cert"] is True
        assert cargs["ssl_verify_identity"] is True


def test_invalid_database_url_raises_startup_error():
    """Verify that an unparseable database URL raises an immediate startup error rather than being silently ignored."""
    with pytest.raises(ValueError) as excinfo:
        create_db_engine("invalid_scheme_without_proper_url")
    assert "CRITICAL STARTUP ERROR" in str(excinfo.value)
