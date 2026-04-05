from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "5000"))
    db_path: str = os.getenv("SCAN_HISTORY_DB", "scan_history.db")
    gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    groq_api_key: Optional[str] = os.getenv("GROQ_API_KEY")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    scan_mode: str = os.getenv("SCAN_MODE", "SAFE_MODE").strip().upper()
    max_active_jobs: int = int(os.getenv("MAX_ACTIVE_JOBS", "3"))
    max_stored_jobs: int = int(os.getenv("MAX_STORED_JOBS", "50"))


SETTINGS = Settings()
