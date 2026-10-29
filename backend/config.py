import os
from pathlib import Path
from urllib.parse import quote_plus
from dotenv import load_dotenv

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

# Exact MySQL Connection Settings
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "autorecon")
DB_USER = os.getenv("DB_USER", "autorecon_app")
DB_PASSWORD = os.getenv("DB_PASSWORD", "autorecon_secure_password_2026")

# SQLAlchemy Connection Pool Settings
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))

def build_database_url(
    user: str = DB_USER,
    password: str = DB_PASSWORD,
    host: str = DB_HOST,
    port: int = DB_PORT,
    name: str = DB_NAME
) -> str:
    encoded_user = quote_plus(user)
    encoded_pass = quote_plus(password)
    return f"mysql+pymysql://{encoded_user}:{encoded_pass}@{host}:{port}/{name}?charset=utf8mb4"

# Authoritative MySQL Connection URL
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

# ML Model artifact directory
ML_MODELS_DIR = BASE_DIR / "ml" / "saved_models"
ML_MODELS_DIR.mkdir(parents=True, exist_ok=True)

CORS_ORIGINS = [
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
    "null",
    "*"
]
