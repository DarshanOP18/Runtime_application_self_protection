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

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel

from app.config import get_settings
from app.database.connection import DatabaseManager
import pyotp
from app.utils.crypto import (
    encrypt_secret,
    decrypt_secret,
    generate_backup_codes,
    hash_backup_code,
    verify_backup_code,
)

router = APIRouter(prefix="/auth", tags=["Auth"])
_bearer = HTTPBearer(auto_error=False)
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
_db_manager: DatabaseManager | None = None

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


def set_auth_db(db: DatabaseManager) -> None:
    """Set the shared database manager used by auth/RBAC helper queries."""
    global _db_manager
    _db_manager = db


def _get_db_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path=_db_path())
    return _db_manager


async def _db_query(sql: str, params: tuple = ()) -> list[dict]:
    return await _get_db_manager().execute_query(sql, params)


async def _db_execute(sql: str, params: tuple = ()) -> int:
    return await _get_db_manager().execute_write(sql, params)


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
                  u.organization, u.is_active, s.expires_at, s.session_token,
                  u.mfa_enabled, s.mfa_verified
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
    if user["mfa_enabled"] == 1 and not user["mfa_verified"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="MFA verification required")
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

    mfa_enabled = user["mfa_enabled"] == 1
    mfa_verified = 0 if mfa_enabled else 1

    await _db_execute(
        """INSERT INTO dashboard_sessions
           (user_id, session_token, expires_at, ip_address, user_agent, mfa_verified)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user["id"], token, expires_at, ip,
         request.headers.get("user-agent", ""), mfa_verified),
    )
    await _db_execute(
        "UPDATE dashboard_users SET last_login=datetime('now'), login_count=login_count+1 WHERE id=?",
        (user["id"],),
    )
    
    if mfa_enabled:
        return JSONResponse({
            "status": "MFA_REQUIRED",
            "intermediate_token": token,
            "username": user["username"]
        })

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


# ── MFA Pydantic Models ───────────────────────────────────────────────────

class MFAVerifyEnrollRequest(BaseModel):
    code: str


class MFALoginRequest(BaseModel):
    intermediate_token: str
    code: str


class MFAResetRequest(BaseModel):
    user_id: int


# ── MFA Routes ─────────────────────────────────────────────────────────────

@router.post("/mfa/enroll", summary="Start MFA TOTP enrollment")
async def mfa_enroll(
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    """Generate a fresh TOTP secret for user and return the otpauth pairing URI."""
    # Ensure they aren't already fully enrolled to prevent key overrides
    if user["mfa_enabled"] == 1:
        raise HTTPException(status_code=400, detail="MFA is already enrolled and active")

    secret = pyotp.random_base32()
    encrypted_secret = encrypt_secret(secret)

    # Save encrypted secret temporarily in DB (enabled is still 0)
    await _db_execute(
        "UPDATE dashboard_users SET mfa_secret_encrypted=? WHERE id=?",
        (encrypted_secret, user["id"]),
    )

    # Create the otpauth:// URI
    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["email"],
        issuer_name="ShieldRASP"
    )

    return JSONResponse({
        "secret": secret,
        "otpauth_url": otpauth_url
    })


@router.post("/mfa/verify-enrollment", summary="Confirm MFA TOTP enrollment")
async def mfa_verify_enrollment(
    body: MFAVerifyEnrollRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    """Verify code from authenticator app, enable MFA, and return backup codes."""
    if user["mfa_enabled"] == 1:
        raise HTTPException(status_code=400, detail="MFA is already enrolled and active")

    rows = await _db_query(
        "SELECT mfa_secret_encrypted FROM dashboard_users WHERE id = ?",
        (user["id"],)
    )
    if not rows or not rows[0]["mfa_secret_encrypted"]:
        raise HTTPException(status_code=400, detail="MFA enrollment not initiated. Call /mfa/enroll first.")

    encrypted_secret = rows[0]["mfa_secret_encrypted"]
    try:
        secret = decrypt_secret(encrypted_secret)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decrypt MFA secret")

    totp = pyotp.TOTP(secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # Generate 8 recovery backup codes
    raw_backup_codes = generate_backup_codes()
    hashed_backup_codes = [hash_backup_code(c) for c in raw_backup_codes]
    import json
    backup_codes_json = json.dumps(hashed_backup_codes)

    # Enable MFA and save recovery hashes
    await _db_execute(
        """UPDATE dashboard_users 
           SET mfa_enabled=1, mfa_backup_codes=?, mfa_enrolled_at=datetime('now')
           WHERE id=?""",
        (backup_codes_json, user["id"]),
    )

    # Mark the current session as verified as well
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if token:
        await _db_execute(
            "UPDATE dashboard_sessions SET mfa_verified=1 WHERE session_token=?",
            (token,),
        )

    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "MFA_ENROLLED", "auth", ip_address=ip)

    return JSONResponse({
        "success": True,
        "backup_codes": raw_backup_codes
    })


@router.post("/mfa/login", summary="Second-factor MFA verification")
async def mfa_login(body: MFALoginRequest, request: Request) -> JSONResponse:
    """Verify 6-digit TOTP or backup recovery code to complete login."""
    ip = request.client.host if request.client else "unknown"
    
    # 1. Fetch intermediate session
    rows = await _db_query(
        """SELECT s.id as session_id, s.user_id, s.expires_at,
                  u.username, u.email, u.full_name, u.role, u.organization,
                  u.mfa_secret_encrypted, u.mfa_backup_codes
           FROM dashboard_sessions s
           JOIN dashboard_users u ON u.id = s.user_id
           WHERE s.session_token = ? AND s.is_active = 1 AND s.mfa_verified = 0""",
        (body.intermediate_token,),
    )
    if not rows:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired intermediate session")

    session = rows[0]
    now = datetime.now(timezone.utc).isoformat()
    if session["expires_at"] < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Intermediate session expired")

    # 2. Check if user is using a backup recovery code
    import json
    backup_codes = []
    if session["mfa_backup_codes"]:
        try:
            backup_codes = json.loads(session["mfa_backup_codes"])
        except Exception:
            backup_codes = []

    matched_backup = False
    if len(body.code) == 8:  # Backup codes are 8 hex characters
        for idx, hashed_code in enumerate(backup_codes):
            if verify_backup_code(body.code, hashed_code):
                backup_codes.pop(idx)
                matched_backup = True
                break

    # 3. If not backup, verify TOTP
    if not matched_backup:
        if not session["mfa_secret_encrypted"]:
            raise HTTPException(status_code=500, detail="MFA secret not configured properly")
        
        try:
            secret = decrypt_secret(session["mfa_secret_encrypted"])
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to decrypt MFA secret")

        totp = pyotp.TOTP(secret)
        if not totp.verify(body.code, valid_window=1):
            await _audit(session["user_id"], session["username"], session["role"],
                         "MFA_FAILED", "auth", ip_address=ip, details="Failed second-factor verify")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid verification code")

    # 4. Success verification
    # Update backup codes JSON if one was used
    if matched_backup:
        await _db_execute(
            "UPDATE dashboard_users SET mfa_backup_codes=? WHERE id=?",
            (json.dumps(backup_codes), session["user_id"]),
        )
        await _audit(session["user_id"], session["username"], session["role"],
                     "MFA_RECOVERY_USED", "auth", ip_address=ip)

    # Elevate session state to verified
    await _db_execute(
        "UPDATE dashboard_sessions SET mfa_verified=1 WHERE id=?",
        (session["session_id"],),
    )

    await _audit(session["user_id"], session["username"], session["role"],
                 "LOGIN_MFA_SUCCESS", "auth", ip_address=ip)

    return JSONResponse({
        "token": body.intermediate_token,
        "user": {
            "id": session["user_id"],
            "username": session["username"],
            "full_name": session["full_name"],
            "email": session["email"],
            "role": session["role"],
            "organization": session["organization"],
            "permissions": build_permissions(session["role"]),
        },
        "expires_at": session["expires_at"],
    })


@router.post("/mfa/reset", summary="Admin reset of user MFA profile")
async def mfa_reset(
    body: MFAResetRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    """Administrative override to reset/disable a user's MFA settings."""
    # Enforce admin roles only
    if user["role"] not in ["SUPER_ADMIN", "SECURITY_ADMIN"]:
        raise HTTPException(status_code=403, detail="Only admins can reset MFA profiles")

    # Fetch user details to log and reset
    rows = await _db_query(
        "SELECT id, username, role FROM dashboard_users WHERE id = ?",
        (body.user_id,)
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Target user not found")
    target_user = rows[0]

    # Enforce role hierarchy (Security Admin cannot reset Super Admin)
    if target_user["role"] == "SUPER_ADMIN" and user["role"] != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Security Admins cannot reset Super Admin profiles")

    await _db_execute(
        """UPDATE dashboard_users 
           SET mfa_enabled=0, mfa_secret_encrypted=NULL, mfa_backup_codes=NULL, mfa_enrolled_at=NULL
           WHERE id=?""",
        (body.user_id,),
    )

    # Invalidate any active sessions for the target user to force relogin
    await _db_execute(
        "UPDATE dashboard_sessions SET is_active=0 WHERE user_id=?",
        (body.user_id,),
    )

    ip = request.client.host if request.client else "unknown"
    await _audit(user["id"], user["username"], user["role"],
                 "MFA_RESET_BY_ADMIN", "auth", ip_address=ip,
                 details=f"Reset MFA profile for user: '{target_user['username']}'")

    return JSONResponse({
        "success": True,
        "message": f"MFA profile successfully reset for user '{target_user['username']}'"
    })
