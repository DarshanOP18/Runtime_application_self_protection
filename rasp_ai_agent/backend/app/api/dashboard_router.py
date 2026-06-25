"""
app/api/dashboard_router.py
───────────────────────────
FastAPI router that powers the web-based security dashboard.

All data is served directly from the existing SQLite database through the
same ThreatRepository and ChatRepository used by the security router.

Endpoints
---------
GET /dashboard                → Serve dashboard.html (static file)
GET /dashboard/api/stats      → Aggregated summary statistics
GET /dashboard/api/threats    → Recent threat events (paginated)
GET /dashboard/api/devices    → All known device profiles
GET /dashboard/api/timeline   → Threat count by hour for the last 24 h
GET /dashboard/api/health     → Live health status for the status bar
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse

from app.config import get_settings

logger = logging.getLogger("rasp.dashboard")

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

# Path to the static folder (sibling of the `app` package)
_STATIC = Path(__file__).resolve().parent.parent.parent / "static"

# ── Runtime references injected by main.py ────────────────────────────
_db_path: str | None = None
_start_time: float = time.time()


def set_dashboard_db(db_path: str) -> None:
    """Inject the SQLite database path so the dashboard can query it directly.

    Parameters
    ----------
    db_path : str
        Absolute or relative path to the SQLite file.
    """
    global _db_path, _start_time
    _db_path = db_path
    _start_time = time.time()


# ═══════════════════════════════════════════════════════════════════════
# Helper — raw SQL query
# ═══════════════════════════════════════════════════════════════════════

async def _query(sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Execute a read-only SQL query and return rows as dicts.

    Parameters
    ----------
    sql : str
        SQL SELECT statement.
    params : tuple
        Positional bind parameters.

    Returns
    -------
    list[dict]
        Each row as a column-name → value mapping.

    Raises
    ------
    HTTPException
        503 if the database is not yet initialised.
    """
    if not _db_path:
        raise HTTPException(status_code=503, detail="Database not initialised yet.")
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def _scalar(sql: str, params: tuple = (), default: Any = 0) -> Any:
    """Return the first column of the first row, or *default* if no rows.

    Parameters
    ----------
    sql : str
        SQL query expected to return a single value.
    params : tuple
        Positional bind parameters.
    default : Any
        Value returned when the query produces no rows.

    Returns
    -------
    Any
        The single scalar value.
    """
    rows = await _query(sql, params)
    if rows:
        return list(rows[0].values())[0]
    return default


# ═══════════════════════════════════════════════════════════════════════
# ROUTE 1 — Serve dashboard.html
# ═══════════════════════════════════════════════════════════════════════

@router.get("", include_in_schema=False)
@router.get("/", include_in_schema=False)
async def serve_dashboard() -> FileResponse:
    """Serve the dashboard HTML file.

    Returns
    -------
    FileResponse
        The static dashboard.html file.

    Raises
    ------
    HTTPException
        404 if dashboard.html is missing from the static folder.
    """
    html_path = _STATIC / "dashboard.html"
    if not html_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"dashboard.html not found at {html_path}. "
                   "Ensure the static/ folder exists beside the backend/ folder.",
        )
    return FileResponse(str(html_path), media_type="text/html")


# ═══════════════════════════════════════════════════════════════════════
# ROUTE 2 — GET /dashboard/api/stats
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/stats", summary="Dashboard aggregated statistics")
async def get_stats() -> JSONResponse:
    """Return aggregated summary numbers for the dashboard cards.

    Returns
    -------
    JSONResponse
        total_threats, critical_count, high_count, unique_devices,
        avg_score, llm_mode, uptime_seconds.
    """
    settings = get_settings()

    total = await _scalar("SELECT COUNT(*) FROM threat_history")
    critical = await _scalar(
        "SELECT COUNT(*) FROM threat_history WHERE risk_level = 'CRITICAL'"
    )
    high = await _scalar(
        "SELECT COUNT(*) FROM threat_history WHERE risk_level = 'HIGH'"
    )
    medium = await _scalar(
        "SELECT COUNT(*) FROM threat_history WHERE risk_level = 'MEDIUM'"
    )
    low = await _scalar(
        "SELECT COUNT(*) FROM threat_history WHERE risk_level = 'LOW'"
    )
    devices = await _scalar("SELECT COUNT(DISTINCT device_id) FROM threat_history")
    avg_score = await _scalar(
        "SELECT ROUND(AVG(risk_score), 1) FROM threat_history"
    ) or 0.0
    threats_24h = await _scalar(
        "SELECT COUNT(*) FROM threat_history "
        "WHERE created_at >= datetime('now', '-24 hours')"
    )

    return JSONResponse({
        "total_threats": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "unique_devices": devices,
        "avg_score": avg_score,
        "threats_24h": threats_24h,
        "uptime_seconds": round(time.time() - _start_time, 1),
        "ollama_model": settings.OLLAMA_MODEL,
    })


# ═══════════════════════════════════════════════════════════════════════
# ROUTE 3 — GET /dashboard/api/threats
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/threats", summary="Recent threat events")
async def get_recent_threats(limit: int = 50, offset: int = 0) -> JSONResponse:
    """Return the most recent threat events for the live feed table.

    Parameters
    ----------
    limit : int
        Maximum rows to return (capped at 200).
    offset : int
        Pagination offset.

    Returns
    -------
    JSONResponse
        List of threat event records.
    """
    limit = min(limit, 200)
    rows = await _query(
        """
        SELECT
            id,
            device_id,
            risk_level,
            risk_score,
            active_threats,
            ai_explanation,
            created_at
        FROM threat_history
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return JSONResponse({"threats": rows, "limit": limit, "offset": offset})


# ═══════════════════════════════════════════════════════════════════════
# ROUTE 4 — GET /dashboard/api/devices
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/devices", summary="All device profiles")
async def get_devices() -> JSONResponse:
    """Return all known device security profiles.

    Returns
    -------
    JSONResponse
        List of device profile records ordered by last_seen descending.
    """
    rows = await _query(
        """
        SELECT
            device_id,
            total_scans,
            high_risk_count,
            last_risk_level,
            last_risk_score,
            last_seen
        FROM device_security_profiles
        ORDER BY last_seen DESC
        LIMIT 100
        """
    )
    return JSONResponse({"devices": rows})


# ═══════════════════════════════════════════════════════════════════════
# ROUTE 5 — GET /dashboard/api/timeline
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/timeline", summary="Threat count per hour for last 24 h")
async def get_timeline() -> JSONResponse:
    """Return threat counts grouped by hour for the last 24 hours.

    Returns
    -------
    JSONResponse
        List of {hour, count, critical_count} records.
    """
    rows = await _query(
        """
        SELECT
            strftime('%Y-%m-%dT%H:00:00', created_at) AS hour,
            COUNT(*) AS count,
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN risk_level = 'HIGH'     THEN 1 ELSE 0 END) AS high_count
        FROM threat_history
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour ASC
        """
    )
    return JSONResponse({"timeline": rows})


# ═══════════════════════════════════════════════════════════════════════
# ROUTE 6 — GET /dashboard/api/health
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/health", summary="Live health for dashboard status bar")
async def dashboard_health() -> JSONResponse:
    """Return a compact health status for the dashboard status bar.

    Returns
    -------
    JSONResponse
        db_ok, uptime_seconds, server_time.
    """
    db_ok = False
    try:
        if _db_path:
            async with aiosqlite.connect(_db_path) as db:
                await db.execute("SELECT 1")
            db_ok = True
    except Exception:
        db_ok = False

    return JSONResponse({
        "db_ok": db_ok,
        "uptime_seconds": round(time.time() - _start_time, 1),
        "server_time": datetime.now(timezone.utc).isoformat(),
    })


# ═══════════════════════════════════════════════════════════════════════
# ROUTE 7 — GET /dashboard/api/threat_types
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/threat_types", summary="Threat type frequency breakdown")
async def get_threat_types() -> JSONResponse:
    """Return how many times each threat type has been detected.

    Parses the ``active_threats`` JSON column and tallies each flag.

    Returns
    -------
    JSONResponse
        List of {threat, count} sorted by count descending.
    """
    import json

    rows = await _query(
        "SELECT active_threats FROM threat_history WHERE active_threats IS NOT NULL"
    )
    tally: dict[str, int] = defaultdict(int)
    for row in rows:
        try:
            threats = json.loads(row["active_threats"] or "[]")
            for t in threats:
                tally[t] += 1
        except (json.JSONDecodeError, TypeError):
            continue

    sorted_threats = sorted(
        [{"threat": k, "count": v} for k, v in tally.items()],
        key=lambda x: x["count"],
        reverse=True,
    )
    return JSONResponse({"threat_types": sorted_threats})
