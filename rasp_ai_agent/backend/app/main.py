"""
app/main.py
───────────
FastAPI application entry point for the RASP Security AI Backend.

Configures:
- Lifespan: logging, DB migrations (001-007), DI, bcrypt check.
- CORS: permissive for local dev; restrict to known IPs in prod.
- Middleware: Request-ID, timing.
- Routers: security, dashboard, auth, rbac, incidents, notifications.
- Static files at /static.
- / redirect → /dashboard.
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.ai.local_llm_client import local_llm_client
from app.ai.security_analyst import SecurityAnalystAI
from app.api.auth_router import router as auth_router
from app.api.dashboard_router import router as dashboard_router, set_dashboard_db
from app.api.incidents_router import router as incidents_router
from app.api.notifications_router import router as notifications_router
from app.api.rbac_router import router as rbac_router
from app.api.security_router import router as security_router, set_dependencies
from app.config import get_settings
from app.database.connection import DatabaseManager
from app.threat_engine.scorer import ThreatScorer
from app.utils.logger import setup_logging

logger = logging.getLogger("rasp.main")


# ═══════════════════════════════════════════════════════════════════════════
# Lifespan
# ═══════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    # 1. Logging
    setup_logging(log_level=settings.LOG_LEVEL)
    logger.info("Starting RASP Security AI Backend v%s", settings.APP_VERSION)

    # 2. Database migrations (001-007 auto-discovered)
    db = DatabaseManager()
    applied = await db.run_migrations()
    if applied:
        logger.info("Applied %d migration(s): %s", len(applied), ", ".join(applied))
    else:
        logger.info("Database up to date — no new migrations")

    # 3. AI services
    analyst = SecurityAnalystAI(llm_client=local_llm_client)
    scorer = ThreatScorer()

    # 4. Dependency injection
    set_dependencies(db=db, llm=local_llm_client, analyst=analyst, scorer=scorer)
    set_dashboard_db(settings.DATABASE_PATH)

    # 5. LLM health check
    if await local_llm_client.check_health():
        logger.info("Local LLM connected — model=%s", settings.OLLAMA_MODEL)
    else:
        logger.warning(
            "Local LLM not available at %s — AI features will use rule-based fallbacks",
            settings.OLLAMA_BASE_URL,
        )

    # 6. bcrypt availability check
    try:
        from passlib.context import CryptContext
        CryptContext(schemes=["bcrypt"]).hash("test")
        logger.info("bcrypt OK — dashboard auth ready")
    except Exception as e:
        logger.warning("bcrypt not available: %s — install passlib[bcrypt]", e)

    logger.info("Dashboard: http://0.0.0.0:%s/dashboard", 8001)
    logger.info("RASP Security AI Backend ready")

    yield

    logger.info("Shutting down RASP Security AI Backend")
    await local_llm_client.close()
    logger.info("Cleanup complete")


# ═══════════════════════════════════════════════════════════════════════════
# Application factory
# ═══════════════════════════════════════════════════════════════════════════

def create_app() -> FastAPI:
    application = FastAPI(
        title="RASP Security AI — Shield SDK",
        description=(
            "AI-powered Security Operations Dashboard backend for Flutter RASP "
            "(Runtime Application Self-Protection) applications. "
            "Full RBAC with 9 roles, threat monitoring, incident management, "
            "fraud detection, and compliance reporting."
        ),
        version=get_settings().APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ──────────────────────────────────────────────────────────────
    # Allows local dev + known server subnets
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8001",
            "http://127.0.0.1:8001",
            "http://0.0.0.0:8001",
            "http://10.200.10.155:8001",
            # Add your server subnet here, e.g. "http://10.200.10.155:8001"
            "*",  # Remove in production and list allowed origins explicitly
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request-ID middleware ─────────────────────────────────────────────
    @application.middleware("http")
    async def request_id_middleware(request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # ── Request-timing middleware ─────────────────────────────────────────
    @application.middleware("http")
    async def timing_middleware(request: Request, call_next) -> Response:
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

    # ── Routers ───────────────────────────────────────────────────────────
    application.include_router(security_router)      # /api/v1/security
    application.include_router(dashboard_router)     # /dashboard
    application.include_router(auth_router)          # /auth
    application.include_router(rbac_router)          # /api/v1/rbac
    application.include_router(incidents_router)     # /api/v1/incidents + /fraud + /compliance
    application.include_router(notifications_router) # /api/v1/notifications

    # ── Static files ──────────────────────────────────────────────────────
    from pathlib import Path
    static_dir = Path(__file__).resolve().parent.parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    application.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ── Root redirect to dashboard ────────────────────────────────────────
    @application.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/dashboard")

    return application


# ── Module-level app instance (used by uvicorn) ───────────────────────────
app = create_app()
