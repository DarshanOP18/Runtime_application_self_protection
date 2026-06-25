"""
app/models/schemas.py
─────────────────────
Pydantic v2 request and response schemas for the RASP Security AI Backend.

All models use strict validation.  ``ThreatAnalysisRequest`` performs device-id
sanitisation at the field-validator level so malformed identifiers are rejected
before they reach the database or threat engine.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ═══════════════════════════════════════════════════════════════════════
# REQUEST SCHEMAS
# ═══════════════════════════════════════════════════════════════════════

class ThreatAnalysisRequest(BaseModel):
    """Payload sent by the Flutter RASP SDK after a security scan.

    Attributes
    ----------
    device_id : str
        Unique device identifier (alphanumeric, hyphens, underscores only).
    user_id : int | None
        Optional FK to the ``users`` table.
    root_detected … screenshot_detected : bool
        Individual threat signal flags.
    device_model, os_version, app_version : str | None
        Optional device metadata for profiling.

    Raises
    ------
    ValueError
        If ``device_id`` contains characters outside [a-zA-Z0-9_-].
    """

    device_id: str = Field(..., min_length=1, max_length=128)
    user_id: Optional[int] = None

    # ── Threat flags ───────────────────────────────────────────────────
    root_detected: bool = False
    frida_detected: bool = False
    debugger_detected: bool = False
    emulator_detected: bool = False
    tamper_detected: bool = False
    vpn_detected: bool = False
    proxy_detected: bool = False
    overlay_detected: bool = False
    accessibility_abuse: bool = False
    hook_detected: bool = False
    location_spoof: bool = False
    time_spoof: bool = False
    malware_detected: bool = False
    screenshot_detected: bool = False

    # ── Device metadata ────────────────────────────────────────────────
    device_model: Optional[str] = None
    os_version: Optional[str] = None
    app_version: Optional[str] = None

    @field_validator("device_id")
    @classmethod
    def sanitize_device_id(cls, v: str) -> str:
        """Allow only alphanumeric characters, hyphens, and underscores.

        Parameters
        ----------
        v : str
            Raw device_id value from the request body.

        Returns
        -------
        str
            The validated (unchanged) device_id.

        Raises
        ------
        ValueError
            When the value contains disallowed characters.
        """
        if not re.match(r"^[a-zA-Z0-9\-_]+$", v):
            raise ValueError("Invalid device_id format — only alphanumeric, hyphens, and underscores are allowed")
        return v


class SecurityChatRequest(BaseModel):
    """Payload for the interactive security Q&A chat endpoint.

    Attributes
    ----------
    message : str
        The user's security question (1–1000 characters).
    session_id : str
        Chat session identifier for context continuity.
    device_id : str | None
        Optional device_id for device-aware answers.
    user_id : int | None
        Optional FK to ``users`` table.
    """

    message: str = Field(..., min_length=1, max_length=1000)
    session_id: str = Field(..., min_length=1, max_length=128)
    device_id: Optional[str] = None
    user_id: Optional[int] = None


# ═══════════════════════════════════════════════════════════════════════
# RESPONSE SCHEMAS
# ═══════════════════════════════════════════════════════════════════════

class ThreatAnalysisResponse(BaseModel):
    """Full analysis result returned after processing a threat payload.

    Attributes
    ----------
    request_id : str
        Unique UUID for this analysis request (for tracing).
    device_id : str
        The device that was analysed.
    risk : str
        Computed risk level — LOW | MEDIUM | HIGH | CRITICAL.
    score : int
        Numeric risk score after multipliers.
    score_breakdown : dict
        Per-threat score contributions, e.g. ``{"root_detected": 50}``.
    active_threats : list[str]
        Names of threat signals that were active.
    title : str
        Short headline for the threat (max ~10 words).
    summary : str
        Plain-English one-line summary.
    explanation : str
        Non-technical explanation (2-3 sentences).
    technical_detail : str
        Technical explanation (2-3 sentences).
    recommendation : list[str]
        Actionable remediation steps.
    remediation_steps : list[dict]
        Structured step-by-step remediation plan.
    threat_id : int
        Primary key of the saved ``threat_history`` row.
    analyzed_at : str
        ISO 8601 timestamp of the analysis.
    """

    request_id: str
    device_id: str
    risk: str
    score: int
    score_breakdown: dict[str, int]
    active_threats: list[str]
    title: str
    summary: str
    explanation: str
    technical_detail: str
    recommendation: list[str]
    remediation_steps: list[dict[str, Any]]
    threat_id: int
    analyzed_at: str


class SecurityChatResponse(BaseModel):
    """Response from the AI security chat endpoint.

    Attributes
    ----------
    session_id : str
        The chat session this response belongs to.
    message_id : int
        Primary key of the assistant message in ``security_chat_history``.
    response : str
        The AI-generated answer.
    suggested_questions : list[str]
        Three follow-up questions the user might want to ask.
    responded_at : str
        ISO 8601 timestamp of the response.
    """

    session_id: str
    message_id: int
    response: str
    suggested_questions: list[str]
    responded_at: str


class ThreatHistoryResponse(BaseModel):
    """Paginated threat history for a specific device.

    Attributes
    ----------
    device_id : str
        The queried device identifier.
    total_events : int
        Total number of threat events recorded for this device.
    events : list[dict]
        Page of threat events with assessment details.
    risk_trend : str
        One of IMPROVING | WORSENING | STABLE, based on recent events.
    most_common_threat : str | None
        The threat signal that has appeared most frequently.
    """

    device_id: str
    total_events: int
    events: list[dict[str, Any]]
    risk_trend: str
    most_common_threat: Optional[str] = None


class HealthResponse(BaseModel):
    """System health check result.

    Attributes
    ----------
    status : str
        Overall status — ``healthy``, ``degraded``, or ``unhealthy``.
    agent_available : bool
        Whether the security analyst agent can answer requests.
    agent_mode : str
        ``local_llm`` when Qwen is connected, ``fallback`` when the local
        rule-based agent is active, or ``offline`` when unavailable.
    llm_available : bool
        Whether the local Ollama/Qwen service responded to a ping.
    database_connected : bool
        Whether the SQLite database is accessible.
    version : str
        Application version string.
    uptime_seconds : float
        Seconds since the server started.
    model_loaded : str
        Name of the configured LLM model.
    """

    model_config = ConfigDict(protected_namespaces=())

    status: str
    agent_available: bool
    agent_mode: str
    llm_available: bool
    database_connected: bool
    version: str
    uptime_seconds: float
    model_loaded: str


class DeleteChatResponse(BaseModel):
    """Response after clearing a chat session.

    Attributes
    ----------
    deleted : bool
        Always ``True`` on success.
    session_id : str
        The session that was cleared.
    """

    deleted: bool
    session_id: str
