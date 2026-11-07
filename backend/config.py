import os
import base64
import json
import tempfile
import logging
from pathlib import Path
from typing import Optional, List
from urllib.parse import quote_plus
from dotenv import load_dotenv

logger = logging.getLogger("autorecon.config")

# Base directories
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Load environment variables from project root .env or backend .env
if (PROJECT_ROOT / ".env").exists():
    load_dotenv(PROJECT_ROOT / ".env")
elif (BASE_DIR / ".env").exists():
    load_dotenv(BASE_DIR / ".env")
else:
    load_dotenv()

# Controlled Forensic Storage Directory
STORAGE_DIR = Path(os.getenv("AUTORECON_STORAGE_DIR", BASE_DIR / "storage"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Dataset & Forensic Report Directories (Outside public static web root)
DATASETS_DIR = Path(os.getenv("AUTORECON_DATASETS_DIR", STORAGE_DIR / "datasets"))
DATASETS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR = Path(os.getenv("AUTORECON_REPORTS_DIR", STORAGE_DIR / "reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 50 * 1024 * 1024))  # 50 MB safe limit

# ====================================================================
# DATABASE CONFIGURATION & ENVIRONMENT VARIABLES
# Mandatory Production Variables: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
# No hardcoded password fallback permitted!
# ====================================================================
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "autorecon")
# For local development, default to 'autorecon_app'; for TiDB Cloud, DB_USER is mandatory
DB_USER = os.getenv("DB_USER")
# Password is strictly read from environment variable without hardcoded fallback
DB_PASSWORD = os.getenv("DB_PASSWORD")

# SQLAlchemy Connection Pool Settings (Optimized for Render Free & TiDB Cloud Serverless)
# Render Free spins down after 15 minutes of inactivity and provides 512MB RAM.
# TiDB Cloud load balancers drop idle connections after 5 minutes (300s).
# A pool_size of 5 with 300s recycle prevents stale connections and connection exhaustion.
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "5"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "300"))
DB_CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "10"))

# ====================================================================
# TIDB CLOUD TLS CA CERTIFICATE MANAGEMENT
# ====================================================================
_decoded_ca_cert_path: Optional[str] = None

def is_tidb_cloud(target_url: Optional[str] = None) -> bool:
    """
    Detects whether the target database is TiDB Cloud by inspecting:
    1. An explicitly passed target_url (e.g. from create_db_engine)
    2. The configured DATABASE_URL environment variable
    3. Host/port configuration (DB_HOST, DB_PORT)
    4. Explicit TiDB environment flags
    """
    url_to_check = target_url or os.getenv("DATABASE_URL")
    if url_to_check:
        # SQLite URLs are never TiDB
        if url_to_check.startswith("sqlite"):
            return False
        try:
            from sqlalchemy.engine import make_url
            u = make_url(url_to_check)
            host = (u.host or "").lower()
            port = u.port
            if "tidbcloud.com" in host or "tidb" in host:
                return True
            if port == 4000 and host not in ("127.0.0.1", "localhost", "mysql", "db"):
                return True
            # If target_url points to local host explicitly, it is not TiDB Cloud
            if host in ("127.0.0.1", "localhost"):
                return False
        except Exception:
            lower_url = url_to_check.lower()
            if "tidbcloud.com" in lower_url or ":4000" in lower_url:
                return True

    # Check environment configuration
    host = (DB_HOST or "").lower()
    if "tidbcloud.com" in host or "tidb" in host:
        return True
    if DB_PORT == 4000 and host not in ("127.0.0.1", "localhost", "mysql", "db"):
        return True
    if os.getenv("IS_TIDB", "").lower() in ("true", "1", "yes"):
        return True
    if os.getenv("TIDB_CA_CERT_BASE64") or os.getenv("TIDB_CA_CERT_PATH"):
        if host not in ("127.0.0.1", "localhost"):
            return True

    return False

def validate_ca_cert_pem(pem_bytes: bytes) -> None:
    """
    Validates that the provided bytes contain a valid, parseable X.509 PEM certificate
    using Python's SSL context facilities.
    Raises ValueError if empty, malformed, corrupt, or contains no certificates.
    """
    import ssl
    if not pem_bytes or not pem_bytes.strip():
        raise ValueError("CA certificate content is empty.")

    try:
        pem_text = pem_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"CA certificate is not valid UTF-8 text: {e}")

    if "-----BEGIN CERTIFICATE-----" not in pem_text or "-----END CERTIFICATE-----" not in pem_text:
        raise ValueError("CA certificate does not contain standard PEM header/footer ('-----BEGIN CERTIFICATE-----').")

    # Use a clean SSLContext to strictly parse X.509 ASN.1 structure via OpenSSL C-bindings
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=pem_text)
        certs = ctx.get_ca_certs()
        if not certs:
            raise ValueError("No valid X.509 CA certificates could be parsed from the provided PEM data.")
    except ssl.SSLError as e:
        raise ValueError(f"Failed to parse X.509 CA certificate: {e}")

def get_ca_cert_path() -> Optional[str]:
    """
    Decodes and validates the TIDB_CA_CERT_BASE64 environment variable at runtime into a temporary PEM file.
    Validates X.509 PEM integrity using Python SSL facilities before returning.
    Returns the absolute path to the validated CA certificate file, or None if not configured.
    """
    global _decoded_ca_cert_path
    if _decoded_ca_cert_path and os.path.exists(_decoded_ca_cert_path):
        return _decoded_ca_cert_path

    # 1. Direct path override if specified
    ca_path_env = os.getenv("TIDB_CA_CERT_PATH") or os.getenv("DB_SSL_CA")
    if ca_path_env:
        resolved = Path(ca_path_env).resolve()
        if not resolved.exists():
            raise ValueError(f"CRITICAL STARTUP ERROR: CA certificate file specified in TIDB_CA_CERT_PATH does not exist: {ca_path_env}")
        cert_bytes = resolved.read_bytes()
        validate_ca_cert_pem(cert_bytes)
        _decoded_ca_cert_path = str(resolved)
        return _decoded_ca_cert_path

    # 2. Base64 environment variable
    ca_b64 = os.getenv("TIDB_CA_CERT_BASE64")
    if not ca_b64:
        return None

    raw_val = ca_b64.strip()
    if not raw_val:
        raise ValueError("CRITICAL STARTUP ERROR: TIDB_CA_CERT_BASE64 is empty.")

    try:
        # If it's already plain PEM text
        if raw_val.startswith("-----BEGIN"):
            cert_bytes = raw_val.encode("utf-8")
        else:
            # Strip whitespace, newlines, carriage returns
            clean_b64 = "".join(raw_val.split())
            # Enforce strict base64 decoding with validation
            pad = len(clean_b64) % 4
            if pad:
                clean_b64 += "=" * (4 - pad)
            cert_bytes = base64.b64decode(clean_b64, validate=True)

        # Validate PEM with Python SSL facilities
        validate_ca_cert_pem(cert_bytes)

        # Write to a secure temporary file
        tmp_dir = Path(tempfile.gettempdir())
        target_file = tmp_dir / "autorecon_tidb_ca.pem"
        target_file.write_bytes(cert_bytes)

        _decoded_ca_cert_path = str(target_file.resolve())
        logger.info(f"Successfully decoded and validated TiDB CA certificate into temporary file: {_decoded_ca_cert_path}")
        return _decoded_ca_cert_path
    except Exception as e:
        raise ValueError(f"CRITICAL STARTUP ERROR: Invalid CA certificate in TIDB_CA_CERT_BASE64: {e}")

def build_database_url(
    user: Optional[str] = None,
    password: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    name: Optional[str] = None
) -> str:
    target_host = host or DB_HOST
    target_port = port or DB_PORT
    target_is_tidb = (
        "tidbcloud.com" in (target_host or "").lower() or
        "tidb" in (target_host or "").lower() or
        (target_port == 4000 and target_host not in ("127.0.0.1", "localhost", "mysql", "db")) or
        is_tidb_cloud()
    )

    if user is None:
        user = DB_USER
        if not user and not target_is_tidb:
            user = "autorecon_app"

    password = password if password is not None else DB_PASSWORD
    host = target_host
    port = target_port
    name = name or DB_NAME

    missing = []
    if not user:
        if target_is_tidb:
            missing.append("DB_USER (required for TiDB Cloud, e.g. <prefix>.root; no default username is assumed)")
        else:
            missing.append("DB_USER")
    if password is None or password == "":
        missing.append("DB_PASSWORD")
    if not host:
        missing.append("DB_HOST")
    if not port:
        missing.append("DB_PORT")
    if not name:
        missing.append("DB_NAME")

    if missing:
        raise ValueError(
            f"CRITICAL STARTUP ERROR: Missing required database credential(s): {', '.join(missing)}. "
            f"Hardcoded database password fallback has been removed for security. "
            f"Please configure DB_PASSWORD and required connection settings in your environment variables."
        )

    # Validate TiDB Cloud CA Certificate if TiDB Cloud is targeted
    if target_is_tidb and not get_ca_cert_path():
        raise ValueError(
            "CRITICAL STARTUP ERROR: TiDB Cloud deployment requires mandatory TLS certificate verification, "
            "but no CA certificate was configured. Please supply the CA certificate via the TIDB_CA_CERT_BASE64 "
            "environment variable."
        )

    encoded_user = quote_plus(user)
    encoded_pass = quote_plus(password)
    return f"mysql+pymysql://{encoded_user}:{encoded_pass}@{host}:{port}/{name}?charset=utf8mb4"

# Authoritative Database Connection URL
DATABASE_URL = os.getenv("DATABASE_URL") or build_database_url()

def get_database_url_safe(url: str = DATABASE_URL) -> str:
    """Return database URL with password masked for safe logging and status reporting."""
    if "@" in url and "://" in url:
        scheme_user, rest = url.split("://", 1)
        if ":" in rest and "@" in rest:
            user_pass, host_db = rest.split("@", 1)
            if ":" in user_pass:
                u, _ = user_pass.split(":", 1)
                return f"{scheme_user}://{u}:****@{host_db}"
    return url

# Legacy SQLite DB path (retained ONLY for inspection and one-time migration verification)
DB_PATH = Path(os.getenv("AUTORECON_DB_PATH", BASE_DIR / "autorecon.db"))

# ML Model artifact directory (Supports external storage / cloud mounts via AUTORECON_MODELS_DIR)
ML_MODELS_DIR = Path(os.getenv("AUTORECON_MODELS_DIR", BASE_DIR / "ml" / "saved_models"))
ML_MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ====================================================================
# CORS CONFIGURATION (STRICT NO WILDCARD / NO NULL POLICY)
# Supports 'https://auto-recon-ai-frontend.vercel.app' without wildcard origins.
# Supports custom comma-separated origins via CORS_ORIGINS environment variable.
# ====================================================================
PROD_FRONTEND_ORIGIN = "https://auto-recon-ai-frontend.vercel.app"

PRODUCTION_CORS_ORIGINS = [
    PROD_FRONTEND_ORIGIN,
]

LOCAL_DEV_CORS_ORIGINS = [
    PROD_FRONTEND_ORIGIN,
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:8080",
    "http://localhost:3000",
    "http://localhost:5500",
    "http://localhost:5173",
    "http://127.0.0.1",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]

DEFAULT_CORS_ORIGINS = LOCAL_DEV_CORS_ORIGINS

def is_production_environment() -> bool:
    """Detects whether the app is executing in a cloud/production environment."""
    if os.getenv("RENDER") or os.getenv("ENVIRONMENT", "").lower() == "production":
        return True
    if is_tidb_cloud():
        return True
    return False

def parse_cors_origins() -> List[str]:
    raw = os.getenv("CORS_ORIGINS")
    if not raw:
        # In cloud/production, never fall back to localhost defaults; keep production origins explicit
        if is_production_environment():
            return list(PRODUCTION_CORS_ORIGINS)
        return list(DEFAULT_CORS_ORIGINS)

    raw = raw.strip()
    origins = []
    if raw.startswith("[") and raw.endswith("]"):
        try:
            origins = json.loads(raw)
        except Exception:
            origins = [o.strip().strip("'\"") for o in raw[1:-1].split(",") if o.strip()]
    else:
        origins = [o.strip() for o in raw.split(",") if o.strip()]

    # Strictly reject both wildcard '*' and 'null' origins
    rejected_terms = {"*", "null", "'*'", "'null'", '"*"', '"null"'}
    filtered = []
    for o in origins:
        cleaned = o.strip()
        if not cleaned:
            continue
        if cleaned.lower() in rejected_terms or cleaned in rejected_terms:
            logger.warning(f"Insecure CORS origin '{cleaned}' was rejected and excluded from allowed origins.")
            continue
        if cleaned not in filtered:
            filtered.append(cleaned)

    # Ensure production frontend origin is always present
    if PROD_FRONTEND_ORIGIN not in filtered:
        filtered.append(PROD_FRONTEND_ORIGIN)
    return filtered

CORS_ORIGINS = parse_cors_origins()
