"""
app/api/auth_router.py
──────────────────────
Dashboard authentication endpoints.

POST /auth/login          — Verify credentials, create session, return token
POST /auth/logout         — Invalidate session
GET  /auth/me             — Current user + permissions
POST /auth/change-password — Change own password

Shared dependencies (imported by other routers):
  get_current_user(token)      — validate session → user row
  require_permission(module)   — factory: check role has access
  has_permission(role, module) — "full" | "view" | "none"
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel

from app.config import get_settings

router = APIRouter(prefix="/auth", tags=["Auth"])
_bearer = HTTPBearer(auto_error=False)
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Permission matrix ─────────────────────────────────────────────────────
# Values: "full" | "view" | "none"
_PERM: dict[str, dict[str, str]] = {
    "executive_dashboard": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "view", "SOC_ANALYST": "none",
        "FRAUD_MANAGER": "view", "FRAUD_ANALYST": "none",
        "COMPLIANCE_MANAGER": "view", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "live_threat_feed": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "full", "SOC_ANALYST": "full",
        "FRAUD_MANAGER": "view", "FRAUD_ANALYST": "view",
        "COMPLIANCE_MANAGER": "view", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "device_inventory": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "full", "SOC_ANALYST": "full",
        "FRAUD_MANAGER": "view", "FRAUD_ANALYST": "view",
        "COMPLIANCE_MANAGER": "view", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "device_investigation": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "full", "SOC_ANALYST": "full",
        "FRAUD_MANAGER": "full", "FRAUD_ANALYST": "full",
        "COMPLIANCE_MANAGER": "view", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "threat_analytics": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "full", "SOC_ANALYST": "view",
        "FRAUD_MANAGER": "view", "FRAUD_ANALYST": "view",
        "COMPLIANCE_MANAGER": "view", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "fraud_intelligence": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "view",
        "SOC_MANAGER": "view", "SOC_ANALYST": "none",
        "FRAUD_MANAGER": "full", "FRAUD_ANALYST": "full",
        "COMPLIANCE_MANAGER": "none", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "incident_center": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "full", "SOC_ANALYST": "full",
        "FRAUD_MANAGER": "view", "FRAUD_ANALYST": "view",
        "COMPLIANCE_MANAGER": "view", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "ai_security_analyst": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "full", "SOC_ANALYST": "full",
        "FRAUD_MANAGER": "view", "FRAUD_ANALYST": "view",
        "COMPLIANCE_MANAGER": "none", "COMPLIANCE_OFFICER": "none",
        "READ_ONLY_AUDITOR": "none",
    },
    "reports": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "full", "SOC_ANALYST": "view",
        "FRAUD_MANAGER": "full", "FRAUD_ANALYST": "view",
        "COMPLIANCE_MANAGER": "full", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "user_rbac_management": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "none", "SOC_ANALYST": "none",
        "FRAUD_MANAGER": "none", "FRAUD_ANALYST": "none",
        "COMPLIANCE_MANAGER": "none", "COMPLIANCE_OFFICER": "none",
        "READ_ONLY_AUDITOR": "none",
    },
    "system_settings": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "none", "SOC_ANALYST": "none",
        "FRAUD_MANAGER": "none", "FRAUD_ANALYST": "none",
        "COMPLIANCE_MANAGER": "none", "COMPLIANCE_OFFICER": "none",
        "READ_ONLY_AUDITOR": "none",
    },
    "audit_logs": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "view", "SOC_ANALYST": "view",
        "FRAUD_MANAGER": "view", "FRAUD_ANALYST": "view",
        "COMPLIANCE_MANAGER": "full", "COMPLIANCE_OFFICER": "view",
        "READ_ONLY_AUDITOR": "view",
    },
    "compliance_center": {
        "SUPER_ADMIN": "full", "SECURITY_ADMIN": "full",
        "SOC_MANAGER": "view", "SOC_ANALYST": "none",
        "FRAUD_MANAGER": "none", "FRAUD_ANALYST": "none",
        "COMPLIANCE_MANAGER": "full", "COMPLIANCE_OFFICER": "full",
        "READ_ONLY_AUDITOR": "view",
    },
}

# Role level — lower number = higher privilege
_ROLE_LEVEL: dict[str, int] = {
    "SUPER_ADMIN": 1,
    "SECURITY_ADMIN": 2,
    "SOC_MANAGER": 3,
    "FRAUD_MANAGER": 3,
    "COMPLIANCE_MANAGER": 3,
    "SOC_ANALYST": 4,
    "FRAUD_ANALYST": 4,
    "COMPLIANCE_OFFICER": 4,
    "READ_ONLY_AUDITOR": 5,
}


# ── Public helpers ─────────────────────────────────────────────────────────

def has_permission(role: str, module: str) -> str:
    """Return 'full' | 'view' | 'none' for a given role/module pair."""
    return _PERM.get(module, {}).get(role, "none")


def role_level(role: str) -> int:
    return _ROLE_LEVEL.get(role, 99)


def build_permissions(role: str) -> dict[str, str]:
    """Build full permission dict for a role across all modules."""
    return {module: has_permission(role, module) for module in _PERM}


# ── Database helpers ───────────────────────────────────────────────────────

def _db_path() -> str:
    return get_settings().DATABASE_PATH


async def _db_query(sql: str, params: tuple = ()) -> list[dict]:
    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


async def _db_execute(sql: str, params: tuple = ()) -> int:
    async with aiosqlite.connect(_db_path()) as db:
        cur = await db.execute(sql, params)
        await db.commit()
        return cur.lastrowid or 0


async def _audit(
    user_id: Optional[int],
    username: Optional[str],
    role: Optional[str],
    action: str,
    module: str = "",
    resource_id: str = "",
    ip_address: str = "",
    details: str = "",
) -> None:
    await _db_execute(
        """INSERT INTO dashboard_audit_logs
           (user_id, username, role, action, module, resource_id, ip_address, details)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, username, role, action, module, resource_id, ip_address, details),
    )


# ── FastAPI dependency: get_current_user ──────────────────────────────────

async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Validate Bearer token → return dashboard_users row or raise 401."""
    if not creds or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing authentication token")
    token = creds.credentials
    now = datetime.now(timezone.utc).isoformat()
    rows = await _db_query(
        """SELECT u.id, u.username, u.email, u.full_name, u.role,
                  u.organization, u.is_active, s.expires_at, s.session_token
           FROM dashboard_sessions s
           JOIN dashboard_users u ON u.id = s.user_id
           WHERE s.session_token = ? AND s.is_active = 1""",
        (token,),
    )
    if not rows:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired token")
    user = rows[0]
    if user["expires_at"] < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Session expired — please log in again")
    if not user["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Account deactivated")
    return user


def require_permission(module: str, level: str = "view"):
    """Factory: FastAPI dependency that checks module access."""
    async def _check(user: dict = Depends(get_current_user)) -> dict:
        perm = has_permission(user["role"], module)
        if perm == "none":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Insufficient permissions for {module}")
        if level == "full" and perm != "full":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Full access required for {module}")
        return user
    return _check


# ── Pydantic models ────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Routes ─────────────────────────────────────────────────────────────────

@router.post("/login", summary="Dashboard login")
async def login(body: LoginRequest, request: Request) -> JSONResponse:
    ip = request.client.host if request.client else "unknown"
    rows = await _db_query(
        "SELECT * FROM dashboard_users WHERE username = ? AND is_active = 1",
        (body.username,),
    )
    if not rows or not _pwd_ctx.verify(body.password, rows[0]["password_hash"]):
        # Log failed attempt even if user doesn't exist
        uid = rows[0]["id"] if rows else None
        uname = rows[0]["username"] if rows else body.username
        await _audit(uid, uname, None, "LOGIN_FAILED", "auth",
                     ip_address=ip, details=f"Failed login for '{body.username}'")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password")

    user = rows[0]
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()

    await _db_execute(
        """INSERT INTO dashboard_sessions
           (user_id, session_token, expires_at, ip_address, user_agent)
           VALUES (?, ?, ?, ?, ?)""",
        (user["id"], token, expires_at, ip,
         request.headers.get("user-agent", "")),
    )
    await _db_execute(
        "UPDATE dashboard_users SET last_login=datetime('now'), login_count=login_count+1 WHERE id=?",
        (user["id"],),
    )
    await _audit(user["id"], user["username"], user["role"],
                 "LOGIN", "auth", ip_address=ip)

    return JSONResponse({
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user["role"],
            "organization": user["organization"],
            "permissions": build_permissions(user["role"]),
        },
        "expires_at": expires_at,
    })


@router.post("/logout", summary="Dashboard logout")
async def logout(
    request: Request,
    user: dict = Depends(get_current_user),
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> JSONResponse:
    token = creds.credentials if creds else ""
    await _db_execute(
        "UPDATE dashboard_sessions SET is_active=0 WHERE session_token=?",
        (token,),
    )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "LOGOUT", "auth", ip_address=ip)
    return JSONResponse({"success": True})


@router.get("/me", summary="Current user info")
async def me(user: dict = Depends(get_current_user)) -> JSONResponse:
    return JSONResponse({
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
        "organization": user["organization"],
        "permissions": build_permissions(user["role"]),
    })


@router.post("/change-password", summary="Change own password")
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> JSONResponse:
    rows = await _db_query(
        "SELECT password_hash FROM dashboard_users WHERE id = ?", (user["id"],)
    )
    if not rows or not _pwd_ctx.verify(body.current_password, rows[0]["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    new_hash = _pwd_ctx.hash(body.new_password)
    await _db_execute(
        "UPDATE dashboard_users SET password_hash=? WHERE id=?",
        (new_hash, user["id"]),
    )
    # Invalidate all OTHER sessions
    current_token = creds.credentials if creds else ""
    await _db_execute(
        "UPDATE dashboard_sessions SET is_active=0 WHERE user_id=? AND session_token!=?",
        (user["id"], current_token),
    )
    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "PASSWORD_CHANGED", "auth", ip_address=ip)
    return JSONResponse({"success": True, "message": "Password changed successfully"})
