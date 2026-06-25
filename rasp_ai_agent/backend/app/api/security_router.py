"""
app/api/security_router.py
───────────────────────────
FastAPI router with all five REST endpoints for the RASP Security AI Backend.

Endpoints
---------
1. POST /api/v1/security/analyze   — Analyse a threat payload and return AI explanation.
2. POST /api/v1/security/chat      — Interactive security Q&A.
3. GET  /api/v1/security/history/{device_id} — Paginated threat history.
4. GET  /api/v1/security/health     — System health check (no auth).
5. DELETE /api/v1/security/chat/{session_id} — Delete a chat session.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.ai.local_llm_client import LocalLLMClient
from app.ai.security_analyst import SecurityAnalystAI
from app.config import get_settings
from app.database.connection import DatabaseManager
from app.database.repositories.chat_repository import ChatRepository
from app.database.repositories.threat_repository import ThreatRepository
from app.models.schemas import (
    DeleteChatResponse,
    HealthResponse,
    SecurityChatRequest,
    SecurityChatResponse,
    ThreatAnalysisRequest,
    ThreatAnalysisResponse,
    ThreatHistoryResponse,
)
from app.threat_engine.scorer import ThreatScorer
from app.utils.input_sanitizer import InputSanitizer
from app.utils.rate_limiter import RateLimiter

logger = logging.getLogger("rasp.api")

router = APIRouter(prefix="/api/v1/security", tags=["Security"])

# ── Shared instances (injected during app startup via set_dependencies) ─
_db: DatabaseManager | None = None
_llm: LocalLLMClient | None = None
_analyst: SecurityAnalystAI | None = None
_scorer: ThreatScorer | None = None
_threat_repo: ThreatRepository | None = None
_chat_repo: ChatRepository | None = None
_rate_limiter: RateLimiter = RateLimiter()
_start_time: float = time.time()


def set_dependencies(
    db: DatabaseManager,
    llm: LocalLLMClient,
    analyst: SecurityAnalystAI,
    scorer: ThreatScorer,
) -> None:
    """Inject shared dependencies from the application lifespan.

    Called once during application startup.

    Parameters
    ----------
    db : DatabaseManager
        The database manager instance.
    llm : LocalLLMClient
        The local LLM client.
    analyst : SecurityAnalystAI
        The AI analyst service.
    scorer : ThreatScorer
        The threat scoring engine.
    """
    global _db, _llm, _analyst, _scorer, _threat_repo, _chat_repo
    _db = db
    _llm = llm
    _analyst = analyst
    _scorer = scorer
    _threat_repo = ThreatRepository(db)
    _chat_repo = ChatRepository(db)


# ═══════════════════════════════════════════════════════════════════════
# ENDPOINT 1 — POST /analyze
# ═══════════════════════════════════════════════════════════════════════

@router.post(
    "/analyze",
    response_model=ThreatAnalysisResponse,
    summary="Analyse a RASP threat payload",
    description="Receives threat signals from the Flutter app, scores them, "
                "generates an AI explanation, and persists the event.",
)
async def analyze_threat(
    request_body: ThreatAnalysisRequest,
    request: Request,
) -> ThreatAnalysisResponse:
    """Score and explain a threat payload from the Flutter RASP SDK.

    Parameters
    ----------
    request_body : ThreatAnalysisRequest
        Validated threat payload with device_id and boolean flags.
    request : Request
        The raw FastAPI request (for request_id header).
    Returns
    -------
    ThreatAnalysisResponse
        Full analysis result including risk score, AI explanation, and
        remediation plan.

    Raises
    ------
    HTTPException
        429 if rate-limited, 500 on internal errors.
    """
    assert _scorer is not None and _analyst is not None and _threat_repo is not None

    # ── Rate limiting: 30 req/min per device_id ───────────────────────
    if not await _rate_limiter.check(f"analyze:{request_body.device_id}", limit=30, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 30 analysis requests per minute per device.",
        )

    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start = time.time()

    try:
        # ── 1. Score the threat payload ───────────────────────────────
        payload_dict = request_body.model_dump()
        assessment = _scorer.calculate(payload_dict)

        logger.info(
            "Threat scored  device=%s  score=%d  level=%s  threats=%s",
            request_body.device_id, assessment.score, assessment.level,
            assessment.active_threats,
            extra={"request_id": request_id, "device_id": request_body.device_id},
        )

        # ── 2. Get AI explanation ─────────────────────────────────────
        explanation = await _analyst.explain_threat(assessment)

        # ── 3. Generate remediation plan ──────────────────────────────
        remediation = await _analyst.generate_remediation_plan(assessment.active_threats)

        # ── 4. Persist to database ────────────────────────────────────
        ai_response = {
            "title": explanation.title,
            "explanation": explanation.explanation,
            "technical_detail": explanation.technical_detail,
            "recommendation": explanation.recommendation,
            "severity_reason": explanation.severity_reason,
        }

        threat_id = await _threat_repo.save_threat(payload_dict, assessment, ai_response)

        # ── 5. Update device profile ──────────────────────────────────
        await _threat_repo.update_device_profile(
            request_body.device_id, payload_dict, assessment,
        )

        elapsed = time.time() - start
        logger.info(
            "Analysis complete  threat_id=%d  elapsed=%.2fs  source=%s",
            threat_id, elapsed, explanation.source,
            extra={"request_id": request_id, "device_id": request_body.device_id},
        )

        return ThreatAnalysisResponse(
            request_id=request_id,
            device_id=request_body.device_id,
            risk=assessment.level,
            score=assessment.score,
            score_breakdown=assessment.score_breakdown,
            active_threats=assessment.active_threats,
            title=explanation.title,
            summary=assessment.summary,
            explanation=explanation.explanation,
            technical_detail=explanation.technical_detail,
            recommendation=explanation.recommendation,
            remediation_steps=remediation.steps,
            threat_id=threat_id,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Analysis failed: %s", exc, exc_info=True, extra={"request_id": request_id})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Threat analysis failed. Please try again.",
        )


# ═══════════════════════════════════════════════════════════════════════
# ENDPOINT 2 — POST /chat
# ═══════════════════════════════════════════════════════════════════════

@router.post(
    "/chat",
    response_model=SecurityChatResponse,
    summary="Interactive security Q&A chat",
    description="Ask the AI security assistant questions about mobile "
                "security threats, RASP protections, and remediation.",
)
async def security_chat(
    request_body: SecurityChatRequest,
    request: Request,
) -> SecurityChatResponse:
    """Handle an interactive security chat message.

    Loads recent chat history for context, calls the AI, and persists
    both the user message and the AI response.

    Parameters
    ----------
    request_body : SecurityChatRequest
        Chat message with session_id and optional device context.
    request : Request
        The raw FastAPI request.
    Returns
    -------
    SecurityChatResponse
        AI response with suggested follow-up questions.

    Raises
    ------
    HTTPException
        429 if rate-limited, 500 on internal errors.
    """
    assert _analyst is not None and _chat_repo is not None

    # ── Rate limiting: 20 req/min per session_id ──────────────────────
    if not await _rate_limiter.check(f"chat:{request_body.session_id}", limit=20, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 20 chat messages per minute per session.",
        )

    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

    try:
        # Sanitise the message
        clean_message = InputSanitizer.validate_message(request_body.message)

        # ── Save user message ─────────────────────────────────────────
        await _chat_repo.save_message(
            session_id=request_body.session_id,
            role="user",
            message=clean_message,
            device_id=request_body.device_id,
            user_id=request_body.user_id,
        )

        # ── Load last 10 messages for context ─────────────────────────
        history = await _chat_repo.get_session_history(
            request_body.session_id, limit=10,
        )
        # history comes newest-first from the repo; reverse for chronological
        history.reverse()

        # ── Build context for the AI ──────────────────────────────────
        context: dict[str, object] = {}
        if request_body.device_id:
            context["device_id"] = request_body.device_id
        if history:
            context["recent_messages"] = [
                {"role": m["role"], "message": m["message"][:200]}
                for m in history[-6:]  # Last 6 messages for context
            ]

        # ── Call the AI ───────────────────────────────────────────────
        ai_response = await _analyst.answer_security_question(
            question=clean_message,
            context=context if context else None,
        )

        # ── Save AI response ─────────────────────────────────────────
        message_id = await _chat_repo.save_message(
            session_id=request_body.session_id,
            role="assistant",
            message=ai_response,
            device_id=request_body.device_id,
            user_id=request_body.user_id,
        )

        # ── Generate follow-up questions ──────────────────────────────
        suggested = await _analyst.generate_follow_up_questions(clean_message, ai_response)

        logger.info(
            "Chat response  session=%s  msg_id=%d",
            request_body.session_id, message_id,
            extra={"request_id": request_id},
        )

        return SecurityChatResponse(
            session_id=request_body.session_id,
            message_id=message_id,
            response=ai_response,
            suggested_questions=suggested,
            responded_at=datetime.now(timezone.utc).isoformat(),
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Chat failed: %s", exc, exc_info=True, extra={"request_id": request_id})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Chat service temporarily unavailable.",
        )


# ═══════════════════════════════════════════════════════════════════════
# ENDPOINT 3 — GET /history/{device_id}
# ═══════════════════════════════════════════════════════════════════════

@router.get(
    "/history/{device_id}",
    response_model=ThreatHistoryResponse,
    summary="Get threat history for a device",
    description="Returns paginated threat events with risk trend analysis.",
)
async def get_threat_history(
    device_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    risk_level: Optional[str] = Query(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    start_date: Optional[str] = Query(default=None),
    end_date: Optional[str] = Query(default=None),
) -> ThreatHistoryResponse:
    """Fetch paginated threat history for a specific device.

    Parameters
    ----------
    device_id : str
        The device identifier to query.
    limit : int
        Maximum results per page (1-100).
    offset : int
        Pagination offset.
    risk_level : str | None
        Filter by risk level.
    start_date : str | None
        ISO date lower bound.
    end_date : str | None
        ISO date upper bound.
    Returns
    -------
    ThreatHistoryResponse
        Events, total count, risk trend, and most common threat.
    """
    assert _threat_repo is not None

    if not InputSanitizer.validate_device_id(device_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid device_id format.",
        )

    events = await _threat_repo.get_by_device(
        device_id,
        limit=limit,
        offset=offset,
        risk_level=risk_level,
        start_date=start_date,
        end_date=end_date,
    )
    total = await _threat_repo.count_by_device(device_id)
    trend = await _threat_repo.get_risk_trend(device_id)
    most_common = await _threat_repo.get_most_common_threat(device_id)

    return ThreatHistoryResponse(
        device_id=device_id,
        total_events=total,
        events=events,
        risk_trend=trend,
        most_common_threat=most_common,
    )


# ═══════════════════════════════════════════════════════════════════════
# ENDPOINT 4 — GET /health
# ═══════════════════════════════════════════════════════════════════════

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System health check",
    description="Returns system status, local LLM availability, and DB connectivity. "
                "No authentication required.",
)
async def health_check() -> HealthResponse:
    """Check system health without authentication.

    Returns
    -------
    HealthResponse
        Status of all subsystems: database, local LLM, uptime, version.
    """
    settings = get_settings()

    db_ok = False
    llm_ok = False
    agent_ok = _analyst is not None and _scorer is not None

    if _db is not None:
        db_ok = await _db.check_health()

    if _llm is not None:
        llm_ok = await _llm.check_health()

    agent_available = db_ok and agent_ok
    agent_mode = "local_llm" if llm_ok else "fallback" if agent_available else "offline"

    if db_ok and agent_available:
        overall = "healthy"
    elif db_ok:
        overall = "degraded"
    else:
        overall = "unhealthy"

    uptime = time.time() - _start_time

    return HealthResponse(
        status=overall,
        agent_available=agent_available,
        agent_mode=agent_mode,
        llm_available=llm_ok,
        database_connected=db_ok,
        version=settings.APP_VERSION,
        uptime_seconds=round(uptime, 2),
        model_loaded=settings.OLLAMA_MODEL,
    )


# ═══════════════════════════════════════════════════════════════════════
# ENDPOINT 5 — DELETE /chat/{session_id}
# ═══════════════════════════════════════════════════════════════════════

@router.delete(
    "/chat/{session_id}",
    response_model=DeleteChatResponse,
    summary="Delete a chat session",
    description="Removes all messages for the specified session_id.",
)
async def delete_chat_session(
    session_id: str,
) -> DeleteChatResponse:
    """Delete all chat messages belonging to a session.

    Parameters
    ----------
    session_id : str
        The chat session identifier to purge.
    Returns
    -------
    DeleteChatResponse
        Confirmation with the deleted session_id.
    """
    assert _chat_repo is not None

    await _chat_repo.delete_session(session_id)
    logger.info("Chat session deleted  session_id=%s", session_id)

    return DeleteChatResponse(deleted=True, session_id=session_id)
