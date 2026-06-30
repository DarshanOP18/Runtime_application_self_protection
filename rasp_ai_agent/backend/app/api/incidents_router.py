"""
app/api/incidents_router.py
───────────────────────────
Incident management, fraud cases, and compliance reports.

GET  /api/v1/incidents               — List incidents (role-filtered)
POST /api/v1/incidents               — Create incident
PUT  /api/v1/incidents/{id}          — Update incident
GET  /api/v1/incidents/stats         — Incident statistics

GET  /api/v1/fraud/cases             — List fraud cases
POST /api/v1/fraud/cases             — Create fraud case

GET  /api/v1/compliance/reports      — List compliance reports
POST /api/v1/compliance/reports/generate — Generate report
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.api.auth_router import (
    _audit,
    _db_execute,
    _db_query,
    get_current_user,
    has_permission,
)
from app.config import get_settings

router = APIRouter(prefix="/api/v1", tags=["Incidents"])


# ── Pydantic models ────────────────────────────────────────────────────────

class CreateIncidentRequest(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "MEDIUM"
    device_id: Optional[str] = None
    threat_type: Optional[str] = None
    risk_score: Optional[int] = None


class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[int] = None
    severity: Optional[str] = None


class CreateFraudCaseRequest(BaseModel):
    device_id: Optional[str] = None
    fraud_type: str
    risk_level: str = "MEDIUM"
    description: Optional[str] = None


class GenerateReportRequest(BaseModel):
    report_type: str = "Monthly Summary"
    standard: str = "RBI"
    period_start: str   # YYYY-MM-DD
    period_end: str     # YYYY-MM-DD


# ── Helpers ────────────────────────────────────────────────────────────────

def _next_seq(prefix: str, date_str: str, existing_count: int) -> str:
    return f"{prefix}-{date_str}-{str(existing_count + 1).zfill(4)}"


# ═══════════════════════════════════════════════════════════════════════════
# INCIDENTS
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/incidents", summary="List incidents (role-filtered)")
async def list_incidents(
    user: dict = Depends(get_current_user),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[int] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    perm = has_permission(user["role"], "incident_center")
    if perm == "none":
        raise HTTPException(403, "No access to Incident Center")

    where, params = ["1=1"], []

    # SOC_ANALYST sees only their own assigned incidents
    if user["role"] == "SOC_ANALYST":
        where.append("i.assigned_to = ?"); params.append(user["id"])
    elif assigned_to:
        where.append("i.assigned_to = ?"); params.append(assigned_to)

    if status_filter:
        where.append("i.status = ?"); params.append(status_filter)
    if severity:
        where.append("i.severity = ?"); params.append(severity)

    where_sql = " AND ".join(where)
    total_row = await _db_query(
        f"SELECT COUNT(*) AS c FROM incidents i WHERE {where_sql}", tuple(params)
    )
    total = total_row[0]["c"] if total_row else 0

    params_paged = params + [limit, offset]
    rows = await _db_query(
        f"""SELECT i.id, i.incident_number, i.title, i.description,
                   i.severity, i.status, i.device_id, i.threat_type,
                   i.risk_score, i.notes, i.created_at, i.updated_at,
                   i.resolved_at,
                   u.full_name AS assigned_name,
                   u.username  AS assigned_username,
                   c.full_name AS created_name
            FROM incidents i
            LEFT JOIN dashboard_users u ON u.id = i.assigned_to
            LEFT JOIN dashboard_users c ON c.id = i.created_by
            WHERE {where_sql}
            ORDER BY i.created_at DESC
            LIMIT ? OFFSET ?""",
        tuple(params_paged),
    )
    return JSONResponse({"incidents": rows, "total": total, "limit": limit, "offset": offset})


@router.post("/incidents", summary="Create a new incident")
async def create_incident(
    body: CreateIncidentRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    allowed = {"SUPER_ADMIN", "SECURITY_ADMIN", "SOC_MANAGER"}
    if user["role"] not in allowed:
        raise HTTPException(403, "Only SOC Manager or above can create incidents")

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    count_row = await _db_query(
        "SELECT COUNT(*) AS c FROM incidents WHERE incident_number LIKE ?",
        (f"INC-{today}-%",),
    )
    count = count_row[0]["c"] if count_row else 0
    inc_number = _next_seq("INC", today, count)

    inc_id = await _db_execute(
        """INSERT INTO incidents
           (incident_number, title, description, severity, status,
            device_id, threat_type, risk_score, created_by)
           VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)""",
        (inc_number, body.title, body.description, body.severity,
         body.device_id, body.threat_type, body.risk_score, user["id"]),
    )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "INCIDENT_CREATED", "incidents", inc_number, ip,
                 f"Severity: {body.severity}")
    return JSONResponse({"success": True, "incident_id": inc_id,
                         "incident_number": inc_number}, status_code=201)


@router.put("/incidents/{incident_id}", summary="Update incident")
async def update_incident(
    incident_id: int,
    body: UpdateIncidentRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    perm = has_permission(user["role"], "incident_center")
    if perm == "none":
        raise HTTPException(403, "No access")

    target = await _db_query("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not target:
        raise HTTPException(404, "Incident not found")
    inc = target[0]

    # SOC_ANALYST can only update their own
    if user["role"] == "SOC_ANALYST" and inc["assigned_to"] != user["id"]:
        raise HTTPException(403, "Can only update your own assigned incidents")

    fields, params = [], []
    if body.status is not None:
        fields.append("status=?"); params.append(body.status)
        if body.status == "RESOLVED":
            fields.append("resolved_at=datetime('now')")
    if body.notes is not None:
        fields.append("notes=?"); params.append(body.notes)
    if body.severity is not None:
        fields.append("severity=?"); params.append(body.severity)
    if body.assigned_to is not None:
        if user["role"] in {"SOC_MANAGER", "SECURITY_ADMIN", "SUPER_ADMIN"}:
            fields.append("assigned_to=?"); params.append(body.assigned_to)
    fields.append("updated_at=datetime('now')")

    if len(fields) > 1:  # more than just updated_at
        params.append(incident_id)
        await _db_execute(
            f"UPDATE incidents SET {', '.join(fields)} WHERE id=?", tuple(params)
        )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "INCIDENT_UPDATED", "incidents", inc["incident_number"], ip)
    return JSONResponse({"success": True})


@router.get("/incidents/stats", summary="Incident statistics")
async def incident_stats(user: dict = Depends(get_current_user)) -> JSONResponse:
    if has_permission(user["role"], "incident_center") == "none":
        raise HTTPException(403, "No access")
    total   = await _db_query("SELECT COUNT(*) AS c FROM incidents")
    open_c  = await _db_query("SELECT COUNT(*) AS c FROM incidents WHERE status='OPEN'")
    crit    = await _db_query("SELECT COUNT(*) AS c FROM incidents WHERE severity='CRITICAL'")
    res_tod = await _db_query(
        "SELECT COUNT(*) AS c FROM incidents WHERE status='RESOLVED' "
        "AND resolved_at >= datetime('now', '-1 day')"
    )
    by_sev  = await _db_query(
        "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity"
    )
    return JSONResponse({
        "total": total[0]["c"] if total else 0,
        "open": open_c[0]["c"] if open_c else 0,
        "critical": crit[0]["c"] if crit else 0,
        "resolved_today": res_tod[0]["c"] if res_tod else 0,
        "by_severity": by_sev,
    })


# ═══════════════════════════════════════════════════════════════════════════
# FRAUD
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/fraud/cases", summary="List fraud cases")
async def list_fraud_cases(
    user: dict = Depends(get_current_user),
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    perm = has_permission(user["role"], "fraud_intelligence")
    if perm == "none":
        raise HTTPException(403, "No access to Fraud Intelligence")

    where, params = ["1=1"], []
    if user["role"] == "FRAUD_ANALYST":
        where.append("f.assigned_to = ?"); params.append(user["id"])
    if status_filter:
        where.append("f.status = ?"); params.append(status_filter)

    where_sql = " AND ".join(where)
    total_row = await _db_query(
        f"SELECT COUNT(*) AS c FROM fraud_cases f WHERE {where_sql}", tuple(params)
    )
    total = total_row[0]["c"] if total_row else 0

    rows = await _db_query(
        f"""SELECT f.*, u.full_name AS assigned_name
            FROM fraud_cases f
            LEFT JOIN dashboard_users u ON u.id = f.assigned_to
            WHERE {where_sql}
            ORDER BY f.created_at DESC
            LIMIT ? OFFSET ?""",
        tuple(params + [limit, offset]),
    )
    return JSONResponse({"cases": rows, "total": total, "limit": limit, "offset": offset})


@router.post("/fraud/cases", summary="Create fraud case")
async def create_fraud_case(
    body: CreateFraudCaseRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    allowed = {"SUPER_ADMIN", "FRAUD_MANAGER"}
    if user["role"] not in allowed:
        raise HTTPException(403, "Only Fraud Manager or above can create cases")

    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    count_row = await _db_query(
        "SELECT COUNT(*) AS c FROM fraud_cases WHERE case_number LIKE ?",
        (f"FRD-{today}-%",),
    )
    count = count_row[0]["c"] if count_row else 0
    case_number = _next_seq("FRD", today, count)

    case_id = await _db_execute(
        """INSERT INTO fraud_cases
           (case_number, device_id, fraud_type, risk_level, status, description)
           VALUES (?, ?, ?, ?, 'OPEN', ?)""",
        (case_number, body.device_id, body.fraud_type, body.risk_level, body.description),
    )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "FRAUD_CASE_CREATED", "fraud", case_number, ip)
    return JSONResponse({"success": True, "case_id": case_id,
                         "case_number": case_number}, status_code=201)


# ═══════════════════════════════════════════════════════════════════════════
# COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/compliance/reports", summary="List compliance reports")
async def list_compliance_reports(
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    perm = has_permission(user["role"], "compliance_center")
    if perm == "none":
        raise HTTPException(403, "No access to Compliance Center")
    rows = await _db_query(
        """SELECT r.*, u.full_name AS generated_by_name
           FROM compliance_reports r
           LEFT JOIN dashboard_users u ON u.id = r.generated_by
           ORDER BY r.created_at DESC LIMIT 100"""
    )
    return JSONResponse({"reports": rows})


@router.post("/compliance/reports/generate", summary="Generate compliance report")
async def generate_compliance_report(
    body: GenerateReportRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    allowed = {"SUPER_ADMIN", "COMPLIANCE_MANAGER"}
    if user["role"] not in allowed:
        raise HTTPException(403, "Only Compliance Manager or above can generate reports")

    # Gather statistics for the period
    threats = await _db_query(
        "SELECT COUNT(*) AS c FROM threat_history WHERE created_at BETWEEN ? AND ?",
        (body.period_start, body.period_end + " 23:59:59"),
    )
    critical = await _db_query(
        "SELECT COUNT(*) AS c FROM threat_history "
        "WHERE risk_level='CRITICAL' AND created_at BETWEEN ? AND ?",
        (body.period_start, body.period_end + " 23:59:59"),
    )
    devices = await _db_query(
        "SELECT COUNT(DISTINCT device_id) AS c FROM threat_history "
        "WHERE created_at BETWEEN ? AND ?",
        (body.period_start, body.period_end + " 23:59:59"),
    )
    avg_score = await _db_query(
        "SELECT ROUND(AVG(risk_score),1) AS v FROM threat_history "
        "WHERE created_at BETWEEN ? AND ?",
        (body.period_start, body.period_end + " 23:59:59"),
    )

    summary = {
        "period_start": body.period_start,
        "period_end": body.period_end,
        "standard": body.standard,
        "report_type": body.report_type,
        "total_threat_events": threats[0]["c"] if threats else 0,
        "critical_events": critical[0]["c"] if critical else 0,
        "devices_monitored": devices[0]["c"] if devices else 0,
        "average_risk_score": avg_score[0]["v"] if avg_score else 0,
        "organization": user.get("organization", "Default"),
    }

    today = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    report_id = f"RPT-{body.standard}-{today}"

    await _db_execute(
        """INSERT INTO compliance_reports
           (report_id, report_type, standard, period_start, period_end,
            generated_by, summary_data, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'GENERATED')""",
        (report_id, body.report_type, body.standard,
         body.period_start, body.period_end,
         user["id"], json.dumps(summary)),
    )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "REPORT_GENERATED", "compliance", report_id, ip)
    return JSONResponse({"success": True, "report_id": report_id, "summary": summary})
