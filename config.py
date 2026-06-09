import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
    DATA_FOLDER = os.path.join(os.path.dirname(__file__), "data")
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), "data", "analyses.db")
    MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", 5120))
    MAX_FILE_BYTES = MAX_UPLOAD_MB * 1024 * 1024
    MAX_CONTENT_LENGTH = None  # no Flask-level cap; enforced per-chunk in the stream route
    STREAM_CHUNK_SIZE = 1 * 1024 * 1024  # 1 MB
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
