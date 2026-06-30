"""
app/api/notifications_router.py
────────────────────────────────
Notification management for dashboard users.

GET  /api/v1/notifications            — Get unread notifications
PUT  /api/v1/notifications/{id}/read  — Mark one as read
POST /api/v1/notifications/mark-all-read — Mark all read
GET  /api/v1/notifications/count      — Unread badge count
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.api.auth_router import _db_execute, _db_query, get_current_user

router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications"])


@router.get("", summary="Get user notifications")
async def get_notifications(user: dict = Depends(get_current_user)) -> JSONResponse:
    rows = await _db_query(
        """SELECT id, title, message, type, is_read, created_at
           FROM notifications
           WHERE (user_id IS NULL OR user_id = ?)
           ORDER BY created_at DESC LIMIT 50""",
        (user["id"],),
    )
    return JSONResponse({"notifications": rows})


@router.put("/{notif_id}/read", summary="Mark notification as read")
async def mark_read(
    notif_id: int,
    user: dict = Depends(get_current_user),
) -> JSONResponse:
    await _db_execute(
        "UPDATE notifications SET is_read=1 WHERE id=? AND (user_id=? OR user_id IS NULL)",
        (notif_id, user["id"]),
    )
    return JSONResponse({"success": True})


@router.post("/mark-all-read", summary="Mark all notifications as read")
async def mark_all_read(user: dict = Depends(get_current_user)) -> JSONResponse:
    await _db_execute(
        "UPDATE notifications SET is_read=1 WHERE user_id=? OR user_id IS NULL",
        (user["id"],),
    )
    return JSONResponse({"success": True})


@router.get("/count", summary="Unread notification count")
async def notification_count(user: dict = Depends(get_current_user)) -> JSONResponse:
    rows = await _db_query(
        "SELECT COUNT(*) AS c FROM notifications "
        "WHERE is_read=0 AND (user_id=? OR user_id IS NULL)",
        (user["id"],),
    )
    return JSONResponse({"unread": rows[0]["c"] if rows else 0})
