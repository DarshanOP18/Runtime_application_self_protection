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

import json
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
_table_columns_cache: dict[str, set[str]] = {}

_THREAT_FLAG_COLUMNS: tuple[str, ...] = (
    "root_detected",
    "frida_detected",
    "debugger_detected",
    "emulator_detected",
    "tamper_detected",
    "vpn_detected",
    "proxy_detected",
    "overlay_detected",
    "accessibility_abuse",
    "hook_detected",
    "location_spoof",
    "time_spoof",
    "malware_detected",
    "screenshot_detected",
)


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


async def _table_columns(table: str) -> set[str]:
    """Return the set of column names for a table, cached per process."""
    cached = _table_columns_cache.get(table)
    if cached is not None:
        return cached
    rows = await _query(f"PRAGMA table_info({table})")
    columns = {str(row["name"]) for row in rows if "name" in row}
    _table_columns_cache[table] = columns
    return columns


def _active_threats_from_row(row: dict[str, Any]) -> list[str]:
    """Build the active threat list from boolean flag columns."""
    return [column for column in _THREAT_FLAG_COLUMNS if row.get(column)]


async def _latest_threat_snapshot(device_id: str) -> dict[str, Any] | None:
    """Fetch the latest threat row for a device in a schema-compatible way."""
    columns = await _table_columns("threat_history")
    select_cols = [
        "risk_level",
        "risk_score",
        "created_at",
    ]
    if "llm_explanation" in columns:
        select_cols.append("llm_explanation AS ai_explanation")
    elif "ai_explanation" in columns:
        select_cols.append("ai_explanation")
    if "active_threats" in columns:
        select_cols.append("active_threats")
    else:
        select_cols.extend(_THREAT_FLAG_COLUMNS)

    rows = await _query(
        f"""
        SELECT {", ".join(select_cols)}
        FROM threat_history
        WHERE device_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (device_id,),
    )
    if not rows:
        return None

    row = rows[0]
    raw_active = row.get("active_threats")
    if isinstance(raw_active, str):
        try:
            row["active_threats"] = json.loads(raw_active or "[]")
        except json.JSONDecodeError:
            row["active_threats"] = []
    elif raw_active is None:
        row["active_threats"] = _active_threats_from_row(row)
    else:
        row["active_threats"] = list(raw_active) if isinstance(raw_active, list) else _active_threats_from_row(row)

    if not row.get("ai_explanation"):
        row["ai_explanation"] = ""
    return row


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
    columns = await _table_columns("threat_history")
    if "active_threats" in columns:
        rows = await _query(
            """
            SELECT
                id,
                device_id,
                risk_level,
                risk_score,
                active_threats,
                llm_explanation AS ai_explanation,
                threat_summary,
                created_at
            FROM threat_history
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
    else:
        rows = await _query(
            f"""
            SELECT
                id,
                device_id,
                risk_level,
                risk_score,
                llm_explanation AS ai_explanation,
                threat_summary,
                created_at,
                {", ".join(_THREAT_FLAG_COLUMNS)}
            FROM threat_history
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )

    for row in rows:
        raw_active = row.get("active_threats")
        if isinstance(raw_active, str):
            try:
                row["active_threats"] = json.loads(raw_active or "[]")
            except json.JSONDecodeError:
                row["active_threats"] = []
        else:
            row["active_threats"] = _active_threats_from_row(row)
        row["ai_explanation"] = row.get("ai_explanation") or ""

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
            total_threat_events AS total_scans,
            highest_risk_ever,
            is_blocked,
            block_reason,
            trusted,
            last_seen_at AS last_seen
        FROM device_security_profile
        ORDER BY last_seen_at DESC
        LIMIT 100
        """
    )

    for row in rows:
        latest = await _latest_threat_snapshot(row["device_id"])
        if latest:
            row["last_risk_level"] = latest.get("risk_level", row.get("highest_risk_ever", "LOW"))
            row["last_risk_score"] = latest.get("risk_score", 0)
            row["last_active_threats"] = latest.get("active_threats", [])
            row["last_seen"] = latest.get("created_at", row.get("last_seen"))
        else:
            row["last_risk_level"] = row.get("highest_risk_ever", "LOW")
            row["last_risk_score"] = 0
            row["last_active_threats"] = []
        row["high_risk_count"] = await _scalar(
            """
            SELECT COUNT(*)
            FROM threat_history
            WHERE device_id = ?
              AND risk_level IN ('HIGH', 'CRITICAL')
            """,
            (row["device_id"],),
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

    columns = await _table_columns("threat_history")
    tally: dict[str, int] = defaultdict(int)

    if "active_threats" in columns:
        rows = await _query(
            "SELECT active_threats FROM threat_history WHERE active_threats IS NOT NULL"
        )
        for row in rows:
            try:
                threats = json.loads(row["active_threats"] or "[]")
                for t in threats:
                    tally[t] += 1
            except (json.JSONDecodeError, TypeError):
                continue
    else:
        rows = await _query(
            f"SELECT {', '.join(_THREAT_FLAG_COLUMNS)} FROM threat_history"
        )
        for row in rows:
            for column in _THREAT_FLAG_COLUMNS:
                if row.get(column):
                    tally[column] += 1

    sorted_threats = sorted(
        [{"threat": k, "count": v} for k, v in tally.items()],
        key=lambda x: x["count"],
        reverse=True,
    )
    return JSONResponse({"threat_types": sorted_threats})
