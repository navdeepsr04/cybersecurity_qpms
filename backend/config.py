import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DATABASE_URL = os.getenv("QPMS_DATABASE_URL", f"sqlite:///{BASE_DIR / 'qpms.db'}")
SECRET_KEY = os.getenv("QPMS_SECRET_KEY", "CHANGE_ME_dev_only_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Login brute-force protection (Phase 10 hardening)
MAX_LOGIN_ATTEMPTS = int(os.getenv("QPMS_MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = float(os.getenv("QPMS_LOGIN_LOCKOUT_MIN", "5"))

UPLOAD_DIR = BASE_DIR / "uploads"
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf"}
ALLOWED_MIME_TYPES = {"application/pdf"}

CORS_ORIGINS = [
    "http://127.0.0.1:5500", "http://localhost:5500",
    "http://127.0.0.1:8000", "http://localhost:8000",
]