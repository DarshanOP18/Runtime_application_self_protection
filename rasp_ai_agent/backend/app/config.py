"""
app/config.py
─────────────
Central configuration for the RASP Security AI Backend.

Uses Pydantic BaseSettings so every value can be overridden via environment
variables or a `.env` file without touching source code.

Sections
--------
- App metadata (version, debug flag, log level)
- Database paths and migration directory
- Local Ollama / Qwen LLM connection settings
- Security middleware (rate limits)
- Threat engine base scores (one env var per threat type)
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application-wide settings loaded from environment / .env file.

    Every field has a sensible default so the server can start with zero
    configuration for local development.  In production each value should be
    set explicitly via environment variables.

    Attributes
    ----------
    APP_VERSION : str
        Semantic version reported by the health endpoint.
    DEBUG : bool
        Enables debug-level logging and detailed error responses.
    LOG_LEVEL : str
        Python logging level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    DATABASE_PATH : str
        Relative or absolute path to the SQLite database file.
    MIGRATIONS_DIR : str
        Directory containing numbered SQL migration scripts.
    OLLAMA_BASE_URL : str
        Base URL for the local Ollama server.
    OLLAMA_MODEL : str
        Local model name to use, default ``qwen2.5:7b``.
    OLLAMA_TIMEOUT : float
        Maximum seconds to wait for an Ollama response.
    OLLAMA_MAX_RETRIES : int
        Number of retries on transient local LLM failures.
    OLLAMA_MAX_TOKENS : int
        Maximum tokens in the generated response.
    OLLAMA_NUM_GPU : int | None
        Number of model layers requested for GPU offload in Ollama.
    OLLAMA_KEEP_ALIVE : str
        How long Ollama should keep the model loaded.
    OLLAMA_TEMPERATURE_ANALYSIS : float
        Temperature for deterministic threat analysis.
    OLLAMA_TEMPERATURE_CHAT : float
        Temperature for interactive chat.
    DEFAULT_RATE_LIMIT : int
        Maximum requests per window for authenticated callers.
    RATE_LIMIT_WINDOW : int
        Sliding window size in seconds for rate limiting.
    THREAT_SCORE_* : int
        Base risk score for each individual threat signal.
    """

    # ── App ────────────────────────────────────────────────────────────
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── Database ───────────────────────────────────────────────────────
    DATABASE_PATH: str = "./data/rbac_security.db"
    MIGRATIONS_DIR: str = "./migrations"

    # ── Local Ollama / Qwen LLM ───────────────────────────────────────
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"
    OLLAMA_TIMEOUT: float = 120.0
    OLLAMA_MAX_RETRIES: int = 3
    OLLAMA_MAX_TOKENS: int = 1000
    OLLAMA_NUM_GPU: int | None = 999
    OLLAMA_KEEP_ALIVE: str = "30m"
    OLLAMA_TEMPERATURE_ANALYSIS: float = 0.3
    OLLAMA_TEMPERATURE_CHAT: float = 0.5

    # ── Security ───────────────────────────────────────────────────────
    DEFAULT_RATE_LIMIT: int = 100
    RATE_LIMIT_WINDOW: int = 60

    # ── Threat Engine Base Scores ──────────────────────────────────────
    THREAT_SCORE_ROOT: int = 50
    THREAT_SCORE_FRIDA: int = 80
    THREAT_SCORE_DEBUGGER: int = 40
    THREAT_SCORE_TAMPER: int = 60
    THREAT_SCORE_EMULATOR: int = 30
    THREAT_SCORE_VPN: int = 15
    THREAT_SCORE_PROXY: int = 20
    THREAT_SCORE_OVERLAY: int = 25
    THREAT_SCORE_ACCESSIBILITY: int = 25
    THREAT_SCORE_HOOK: int = 70
    THREAT_SCORE_LOCATION_SPOOF: int = 35
    THREAT_SCORE_TIME_SPOOF: int = 30
    THREAT_SCORE_MALWARE: int = 90
    THREAT_SCORE_SCREENSHOT: int = 10

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


# ── Singleton accessor ─────────────────────────────────────────────────
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a cached ``Settings`` instance (singleton).

    Returns
    -------
    Settings
        The application settings loaded from environment / .env.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
