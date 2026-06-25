"""
app/main.py
───────────
FastAPI application entry point for the RASP Security AI Backend.

Configures:
- Lifespan context manager (startup: logging, DB migrations, dependency
  injection; shutdown: local LLM client teardown).
- CORS middleware (allow all origins for development).
- Request-ID middleware (injects ``X-Request-ID`` on every response).
- Request-timing middleware (logs response time in ms).
- Mounts the security router under ``/api/v1``.
- Exposes Swagger UI (``/docs``) and ReDoc (``/redoc``).
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.ai.local_llm_client import local_llm_client
from app.ai.security_analyst import SecurityAnalystAI
from app.api.dashboard_router import router as dashboard_router, set_dashboard_db
from app.api.security_router import router as security_router, set_dependencies
from app.config import get_settings
from app.database.connection import DatabaseManager
from app.threat_engine.scorer import ThreatScorer
from app.utils.logger import setup_logging

logger = logging.getLogger("rasp.main")


# ═══════════════════════════════════════════════════════════════════════
# Lifespan
# ═══════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks.

    Startup
    -------
    1. Initialise structured logging.
    2. Run database migrations.
    3. Create shared local LLM client, AI analyst, and threat scorer.
    4. Inject dependencies into the security router.

    Shutdown
    --------
    1. Close the local LLM HTTP client.

    Parameters
    ----------
    app : FastAPI
        The FastAPI application instance.
    """
    settings = get_settings()

    # ── 1. Logging ────────────────────────────────────────────────────
    setup_logging(log_level=settings.LOG_LEVEL)
    logger.info("Starting RASP Security AI Backend v%s", settings.APP_VERSION)

    # ── 2. Database ───────────────────────────────────────────────────
    db = DatabaseManager()
    applied = await db.run_migrations()
    if applied:
        logger.info("Applied %d migration(s): %s", len(applied), ", ".join(applied))
    else:
        logger.info("Database up to date — no new migrations")

    # ── 3. AI services ────────────────────────────────────────────────
    analyst = SecurityAnalystAI(llm_client=local_llm_client)
    scorer = ThreatScorer()

    # ── 4. Dependency injection ───────────────────────────────────────
    set_dependencies(db=db, llm=local_llm_client, analyst=analyst, scorer=scorer)
    set_dashboard_db(settings.DATABASE_PATH)
    # Check local LLM connectivity
    if await local_llm_client.check_health():
        logger.info("Local LLM connected  model=%s", settings.OLLAMA_MODEL)
    else:
        logger.warning(
            "Local LLM not available at %s — AI features will use rule-based fallbacks",
            settings.OLLAMA_BASE_URL,
        )

    logger.info("RASP Security AI Backend ready")

    yield  # ── Application runs ──────────────────────────────────────

    # ── Shutdown ──────────────────────────────────────────────────────
    logger.info("Shutting down RASP Security AI Backend")
    await local_llm_client.close()
    logger.info("Cleanup complete")


# ═══════════════════════════════════════════════════════════════════════
# Application factory
# ═══════════════════════════════════════════════════════════════════════

def create_app() -> FastAPI:
    """Build and configure the FastAPI application.

    Returns
    -------
    FastAPI
        Fully configured application instance with middleware and routes.
    """
    application = FastAPI(
        title="RASP Security AI Backend",
        description=(
            "AI-powered Security Assistant backend for Flutter RASP "
            "(Runtime Application Self-Protection) applications. "
            "Analyses threat signals, scores risk, and provides "
            "natural-language explanations and remediation guidance."
        ),
        version=get_settings().APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ──────────────────────────────────────────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request-ID middleware ─────────────────────────────────────────
    @application.middleware("http")
    async def request_id_middleware(request: Request, call_next) -> Response:
        """Inject a unique X-Request-ID header into every response.

        If the client provides an ``X-Request-ID`` header, it is passed
        through; otherwise a new UUID is generated.

        Parameters
        ----------
        request : Request
            Incoming HTTP request.
        call_next : callable
            The next middleware / route handler.

        Returns
        -------
        Response
            The response with ``X-Request-ID`` header set.
        """
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # ── Request-timing middleware ─────────────────────────────────────
    @application.middleware("http")
    async def timing_middleware(request: Request, call_next) -> Response:
        """Log the wall-clock time taken by each request.

        Adds ``X-Response-Time`` header (in milliseconds) and logs the
        request summary.

        Parameters
        ----------
        request : Request
            Incoming HTTP request.
        call_next : callable
            The next middleware / route handler.

        Returns
        -------
        Response
            The response with ``X-Response-Time`` header set.
        """
        start = time.time()
        response = await call_next(request)
        elapsed_ms = round((time.time() - start) * 1000, 2)
        response.headers["X-Response-Time"] = f"{elapsed_ms}ms"

        logger.info(
            "%s %s → %d  (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response

    # ── Routes ────────────────────────────────────────────────────────
    application.include_router(security_router)
    application.include_router(dashboard_router)

    # ── Static files (CSS/JS assets if needed in future) ─────────────
    from pathlib import Path
    static_dir = Path(__file__).resolve().parent.parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    application.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @application.get("/", summary="Root Welcome")
    async def welcome():
        return {
            "message": "Welcome to RASP Security AI Backend!",
            "status": "online",
            "docs": "/docs",
            "dashboard": "/dashboard",
            "health": "/api/v1/security/health",
        }

    return application


# ── Module-level app instance (used by uvicorn) ───────────────────────
app = create_app()
