"""
app/api/rbac_router.py
──────────────────────
User management endpoints — SUPER_ADMIN and SECURITY_ADMIN only.

GET  /api/v1/rbac/users              — List all dashboard users
POST /api/v1/rbac/users              — Create a new user
PUT  /api/v1/rbac/users/{user_id}    — Update user
DELETE /api/v1/rbac/users/{user_id}  — Deactivate user (soft delete)
GET  /api/v1/rbac/roles              — List roles with permission matrix
GET  /api/v1/rbac/audit-logs         — Paginated audit logs
"""

from __future__ import annotations

from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel

from app.api.auth_router import (
    _audit,
    _db_execute,
    _db_query,
    build_permissions,
    get_current_user,
    has_permission,
    role_level,
)

router = APIRouter(prefix="/api/v1/rbac", tags=["RBAC"])
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Pydantic models ────────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    full_name: str
    role: str
    organization: str = "Default"


class UpdateUserRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    organization: Optional[str] = None
    is_active: Optional[int] = None


# ── Helpers ────────────────────────────────────────────────────────────────

_VALID_ROLES = {
    "SUPER_ADMIN", "SECURITY_ADMIN", "SOC_MANAGER", "SOC_ANALYST",
    "FRAUD_MANAGER", "FRAUD_ANALYST", "COMPLIANCE_MANAGER",
    "COMPLIANCE_OFFICER", "READ_ONLY_AUDITOR",
}

def _can_manage_role(actor_role: str, target_role: str) -> bool:
    """Actor can only create/manage roles that are strictly lower level."""
    return role_level(actor_role) < role_level(target_role)


# ── Routes ─────────────────────────────────────────────────────────────────

@router.get("/users", summary="List all dashboard users")
async def list_users(user: dict = Depends(get_current_user)) -> JSONResponse:
    if has_permission(user["role"], "user_rbac_management") == "none":
        raise HTTPException(403, "Insufficient permissions")
    rows = await _db_query(
        """SELECT id, username, email, full_name, role, organization,
                  is_active, last_login, login_count, created_at
           FROM dashboard_users ORDER BY created_at DESC"""
    )
    return JSONResponse({"users": rows})


@router.post("/users", summary="Create a new dashboard user")
async def create_user(
    body: CreateUserRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    if has_permission(user["role"], "user_rbac_management") != "full":
        raise HTTPException(403, "Insufficient permissions")
    if body.role not in _VALID_ROLES:
        raise HTTPException(400, f"Invalid role: {body.role}")
    if not _can_manage_role(user["role"], body.role):
        raise HTTPException(403, "Cannot create a user with equal or higher role")
    # Validate uniqueness
    existing = await _db_query(
        "SELECT id FROM dashboard_users WHERE username=? OR email=?",
        (body.username, body.email),
    )
    if existing:
        raise HTTPException(409, "Username or email already exists")
    pw_hash = _pwd_ctx.hash(body.password)
    uid = await _db_execute(
        """INSERT INTO dashboard_users
           (username, email, password_hash, full_name, role, organization, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (body.username, body.email, pw_hash, body.full_name,
         body.role, body.organization, user["id"]),
    )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "USER_CREATED", "rbac", str(uid), ip,
                 f"Created user '{body.username}' with role '{body.role}'")
    return JSONResponse({"success": True, "user_id": uid}, status_code=201)


@router.put("/users/{user_id}", summary="Update a dashboard user")
async def update_user(
    user_id: int,
    body: UpdateUserRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    if has_permission(user["role"], "user_rbac_management") != "full":
        raise HTTPException(403, "Insufficient permissions")
    target = await _db_query("SELECT * FROM dashboard_users WHERE id=?", (user_id,))
    if not target:
        raise HTTPException(404, "User not found")
    t = target[0]
    if not _can_manage_role(user["role"], t["role"]):
        raise HTTPException(403, "Cannot modify user with equal or higher role")
    if body.role and not _can_manage_role(user["role"], body.role):
        raise HTTPException(403, "Cannot assign equal or higher role")

    fields, params = [], []
    if body.full_name is not None:
        fields.append("full_name=?"); params.append(body.full_name)
    if body.role is not None:
        fields.append("role=?"); params.append(body.role)
    if body.organization is not None:
        fields.append("organization=?"); params.append(body.organization)
    if body.is_active is not None:
        fields.append("is_active=?"); params.append(body.is_active)
    if not fields:
        return JSONResponse({"success": True, "message": "Nothing to update"})

    params.append(user_id)
    await _db_execute(f"UPDATE dashboard_users SET {', '.join(fields)} WHERE id=?", tuple(params))
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "USER_UPDATED", "rbac", str(user_id), ip)
    return JSONResponse({"success": True})


@router.delete("/users/{user_id}", summary="Deactivate a dashboard user")
async def deactivate_user(
    user_id: int,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    if user["role"] != "SUPER_ADMIN":
        raise HTTPException(403, "Only Super Admin can deactivate users")
    if user_id == user["id"]:
        raise HTTPException(400, "Cannot deactivate your own account")
    target = await _db_query("SELECT * FROM dashboard_users WHERE id=?", (user_id,))
    if not target:
        raise HTTPException(404, "User not found")
    await _db_execute("UPDATE dashboard_users SET is_active=0 WHERE id=?", (user_id,))
    await _db_execute(
        "UPDATE dashboard_sessions SET is_active=0 WHERE user_id=?", (user_id,)
    )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "USER_DEACTIVATED", "rbac", str(user_id), ip)
    return JSONResponse({"success": True})


@router.get("/roles", summary="List roles with permission matrix")
async def list_roles(user: dict = Depends(get_current_user)) -> JSONResponse:
    roles = []
    for role in [
        "SUPER_ADMIN", "SECURITY_ADMIN", "SOC_MANAGER", "SOC_ANALYST",
        "FRAUD_MANAGER", "FRAUD_ANALYST", "COMPLIANCE_MANAGER",
        "COMPLIANCE_OFFICER", "READ_ONLY_AUDITOR",
    ]:
        count_row = await _db_query(
            "SELECT COUNT(*) AS c FROM dashboard_users WHERE role=? AND is_active=1",
            (role,),
        )
        roles.append({
            "role": role,
            "user_count": count_row[0]["c"] if count_row else 0,
            "permissions": build_permissions(role),
        })
    return JSONResponse({"roles": roles})


@router.get("/audit-logs", summary="Paginated dashboard audit logs")
async def get_audit_logs(
    user: dict = Depends(get_current_user),
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    # Only super admin, security admin, compliance manager can view
    allowed = {"SUPER_ADMIN", "SECURITY_ADMIN", "COMPLIANCE_MANAGER", "COMPLIANCE_OFFICER"}
    if user["role"] not in allowed:
        raise HTTPException(403, "Insufficient permissions for audit logs")

    where, params = ["1=1"], []
    if username:
        where.append("username LIKE ?"); params.append(f"%{username}%")
    if action:
        where.append("action = ?"); params.append(action)
    if module:
        where.append("module = ?"); params.append(module)

    where_sql = " AND ".join(where)
    total_row = await _db_query(
        f"SELECT COUNT(*) AS c FROM dashboard_audit_logs WHERE {where_sql}", tuple(params)
    )
    total = total_row[0]["c"] if total_row else 0

    params.extend([limit, offset])
    rows = await _db_query(
        f"""SELECT id, user_id, username, role, action, module,
                   resource_id, ip_address, details, performed_at
            FROM dashboard_audit_logs
            WHERE {where_sql}
            ORDER BY performed_at DESC
            LIMIT ? OFFSET ?""",
        tuple(params),
    )
    return JSONResponse({"logs": rows, "total": total, "limit": limit, "offset": offset})
