import os
from pathlib import Path
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = Path(os.getenv("AUTORECON_STORAGE_DIR", BASE_DIR / "storage"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# MySQL Connection Settings
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "autorecon_ai")
DB_USER = os.getenv("DB_USER", "autorecon_app")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

# Pool Configuration
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

# If DATABASE_URL is set explicitly in environment, use it; otherwise build from components
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

# Legacy SQLite DB path (kept exclusively for inspection, migration utility and isolated test fixtures)
DB_PATH = Path(os.getenv("AUTORECON_DB_PATH", BASE_DIR / "autorecon.db"))

CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:3000",
    "http://localhost:5500",
    "http://localhost:5173",
    "http://127.0.0.1",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "null",
    "*"
]
