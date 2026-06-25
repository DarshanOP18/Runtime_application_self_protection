"""
app/database/repositories/threat_repository.py
───────────────────────────────────────────────
Data access layer for threat events, risk assessments, and device profiles.

All methods are fully async and use parameterised queries to prevent
SQL injection.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any

from app.database.connection import DatabaseManager
from app.threat_engine.scorer import ThreatAssessment

logger = logging.getLogger("rasp.repository.threat")


class ThreatRepository:
    """Repository for ``threat_history``, ``risk_assessments``, and
    ``device_security_profile`` tables.

    Parameters
    ----------
    db : DatabaseManager
        The shared database manager instance.
    """

    def __init__(self, db: DatabaseManager) -> None:
        """Initialise with a DatabaseManager."""
        self._db = db

    # ── Save threat event ─────────────────────────────────────────────

    async def save_threat(
        self,
        payload: dict[str, Any],
        assessment: ThreatAssessment,
        ai_response: dict[str, Any] | None = None,
    ) -> int:
        """Persist a threat event, its AI explanation, and a risk assessment.

        Parameters
        ----------
        payload : dict
            The original request payload (used for boolean columns and raw JSON).
        assessment : ThreatAssessment
            Scored assessment from the threat engine.
        ai_response : dict | None
            Parsed AI explanation fields (title, explanation, etc.).

        Returns
        -------
        int
            Primary key of the inserted ``threat_history`` row.

        Raises
        ------
        Exception
            Propagates any database write error.
        """
        ai = ai_response or {}

        # ── Insert into threat_history ────────────────────────────────
        threat_id = await self._db.execute_write(
            """
            INSERT INTO threat_history (
                device_id, user_id,
                root_detected, frida_detected, debugger_detected,
                emulator_detected, tamper_detected, vpn_detected,
                proxy_detected, overlay_detected, accessibility_abuse,
                hook_detected, location_spoof, time_spoof,
                malware_detected, screenshot_detected,
                risk_score, risk_level, threat_summary,
                llm_explanation, llm_recommendation, raw_payload
            ) VALUES (
                ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?
            )
            """,
            (
                payload.get("device_id", ""),
                payload.get("user_id"),
                int(payload.get("root_detected", False)),
                int(payload.get("frida_detected", False)),
                int(payload.get("debugger_detected", False)),
                int(payload.get("emulator_detected", False)),
                int(payload.get("tamper_detected", False)),
                int(payload.get("vpn_detected", False)),
                int(payload.get("proxy_detected", False)),
                int(payload.get("overlay_detected", False)),
                int(payload.get("accessibility_abuse", False)),
                int(payload.get("hook_detected", False)),
                int(payload.get("location_spoof", False)),
                int(payload.get("time_spoof", False)),
                int(payload.get("malware_detected", False)),
                int(payload.get("screenshot_detected", False)),
                assessment.score,
                assessment.level,
                assessment.summary,
                ai.get("explanation", ""),
                json.dumps(ai.get("recommendation", []), ensure_ascii=False),
                json.dumps(payload, default=str, ensure_ascii=False),
            ),
        )

        # ── Insert into risk_assessments ──────────────────────────────
        await self._db.execute_write(
            """
            INSERT INTO risk_assessments (
                device_id, threat_id, risk_score, risk_level,
                threat_flags, score_breakdown
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("device_id", ""),
                threat_id,
                assessment.score,
                assessment.level,
                json.dumps(assessment.active_threats, ensure_ascii=False),
                json.dumps(assessment.score_breakdown, ensure_ascii=False),
            ),
        )

        logger.info(
            "Saved threat event  threat_id=%d  device_id=%s  risk=%s(%d)",
            threat_id, payload.get("device_id"), assessment.level, assessment.score,
        )
        return threat_id

    # ── Get history by device ─────────────────────────────────────────

    async def get_by_device(
        self,
        device_id: str,
        limit: int = 50,
        offset: int = 0,
        risk_level: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch threat history for a device with optional filters.

        Parameters
        ----------
        device_id : str
            Target device identifier.
        limit : int
            Maximum rows to return.
        offset : int
            Pagination offset.
        risk_level : str | None
            Filter by risk level (e.g. ``"CRITICAL"``).
        start_date : str | None
            ISO date lower bound (inclusive).
        end_date : str | None
            ISO date upper bound (inclusive).

        Returns
        -------
        list[dict]
            Threat event rows with joined risk assessment data.
        """
        conditions = ["th.device_id = ?"]
        params: list[Any] = [device_id]

        if risk_level:
            conditions.append("th.risk_level = ?")
            params.append(risk_level)
        if start_date:
            conditions.append("th.created_at >= ?")
            params.append(start_date)
        if end_date:
            conditions.append("th.created_at <= ?")
            params.append(end_date)

        where_clause = " AND ".join(conditions)

        return await self._db.execute_query(
            f"""
            SELECT
                th.id, th.device_id, th.risk_score, th.risk_level,
                th.threat_summary, th.llm_explanation, th.llm_recommendation,
                th.created_at,
                ra.threat_flags, ra.score_breakdown
            FROM threat_history th
            LEFT JOIN risk_assessments ra ON ra.threat_id = th.id
            WHERE {where_clause}
            ORDER BY th.created_at DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit, offset]),
        )

    # ── Count events for a device ─────────────────────────────────────

    async def count_by_device(self, device_id: str) -> int:
        """Return the total number of threat events for a device.

        Parameters
        ----------
        device_id : str
            Target device identifier.

        Returns
        -------
        int
            Count of threat events.
        """
        rows = await self._db.execute_query(
            "SELECT COUNT(*) as cnt FROM threat_history WHERE device_id = ?",
            (device_id,),
        )
        return rows[0]["cnt"] if rows else 0

    # ── Risk trend ────────────────────────────────────────────────────

    async def get_risk_trend(self, device_id: str, days: int = 7) -> str:
        """Analyse recent risk scores to determine a trend.

        Compares the average score of the first half and second half of
        recent events.

        Parameters
        ----------
        device_id : str
            Target device identifier.
        days : int
            Look-back window in days.

        Returns
        -------
        str
            ``"IMPROVING"`` | ``"WORSENING"`` | ``"STABLE"``.
        """
        rows = await self._db.execute_query(
            """
            SELECT risk_score FROM threat_history
            WHERE device_id = ?
              AND created_at >= datetime('now', ?)
            ORDER BY created_at ASC
            """,
            (device_id, f"-{days} days"),
        )

        if len(rows) < 2:
            return "STABLE"

        scores = [r["risk_score"] for r in rows]
        mid = len(scores) // 2
        first_half_avg = sum(scores[:mid]) / max(mid, 1)
        second_half_avg = sum(scores[mid:]) / max(len(scores) - mid, 1)

        diff = second_half_avg - first_half_avg
        if diff < -10:
            return "IMPROVING"
        elif diff > 10:
            return "WORSENING"
        return "STABLE"

    # ── Most common threat ────────────────────────────────────────────

    async def get_most_common_threat(self, device_id: str) -> str | None:
        """Find the most frequently occurring threat for a device.

        Parameters
        ----------
        device_id : str
            Target device identifier.

        Returns
        -------
        str | None
            Name of the most common threat, or ``None`` if no events.
        """
        rows = await self._db.execute_query(
            "SELECT threat_flags FROM risk_assessments WHERE device_id = ?",
            (device_id,),
        )
        if not rows:
            return None

        counter: Counter[str] = Counter()
        for row in rows:
            try:
                flags = json.loads(row["threat_flags"]) if isinstance(row["threat_flags"], str) else row["threat_flags"]
                counter.update(flags)
            except (json.JSONDecodeError, TypeError):
                continue

        if not counter:
            return None
        return counter.most_common(1)[0][0]

    # ── Update device security profile ────────────────────────────────

    async def update_device_profile(
        self,
        device_id: str,
        payload: dict[str, Any],
        assessment: ThreatAssessment,
    ) -> None:
        """Create or update the device security profile.

        Uses ``INSERT OR REPLACE`` on the UNIQUE ``device_id`` column.

        Parameters
        ----------
        device_id : str
            Target device identifier.
        payload : dict
            Request payload with device metadata.
        assessment : ThreatAssessment
            Latest scored assessment.
        """
        # Fetch existing profile to preserve cumulative data
        existing = await self._db.execute_query(
            "SELECT * FROM device_security_profile WHERE device_id = ?",
            (device_id,),
        )

        if existing:
            profile = existing[0]
            total_events = profile["total_threat_events"] + 1
            highest = self._higher_risk(profile["highest_risk_ever"], assessment.level)

            await self._db.execute_write(
                """
                UPDATE device_security_profile SET
                    user_id = COALESCE(?, user_id),
                    device_model = COALESCE(?, device_model),
                    os_version = COALESCE(?, os_version),
                    app_version = COALESCE(?, app_version),
                    last_seen_at = datetime('now'),
                    total_threat_events = ?,
                    highest_risk_ever = ?,
                    is_blocked = ?,
                    block_reason = ?
                WHERE device_id = ?
                """,
                (
                    payload.get("user_id"),
                    payload.get("device_model"),
                    payload.get("os_version"),
                    payload.get("app_version"),
                    total_events,
                    highest,
                    1 if assessment.level == "CRITICAL" else profile["is_blocked"],
                    f"Risk level: {assessment.level}" if assessment.level == "CRITICAL" else profile.get("block_reason"),
                    device_id,
                ),
            )
        else:
            await self._db.execute_write(
                """
                INSERT INTO device_security_profile (
                    device_id, user_id, device_model, os_version, app_version,
                    total_threat_events, highest_risk_ever,
                    is_blocked, block_reason
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    device_id,
                    payload.get("user_id"),
                    payload.get("device_model"),
                    payload.get("os_version"),
                    payload.get("app_version"),
                    assessment.level,
                    1 if assessment.level == "CRITICAL" else 0,
                    f"Risk level: {assessment.level}" if assessment.level == "CRITICAL" else None,
                ),
            )

        logger.info("Updated device profile  device_id=%s  events=%s", device_id, "updated")

    @staticmethod
    def _higher_risk(existing: str, new: str) -> str:
        """Return the more severe risk level.

        Parameters
        ----------
        existing : str
            Previously recorded highest risk level.
        new : str
            Risk level from the latest assessment.

        Returns
        -------
        str
            The higher of the two risk levels.
        """
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return new if order.get(new, 0) >= order.get(existing, 0) else existing
