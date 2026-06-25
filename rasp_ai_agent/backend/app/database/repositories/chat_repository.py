"""
app/database/repositories/chat_repository.py
─────────────────────────────────────────────
Data access layer for the ``security_chat_history`` table.

Stores and retrieves chat messages for the AI security Q&A feature.
Messages are keyed by ``session_id`` so multiple conversations can
run concurrently across devices.
"""

from __future__ import annotations

import logging
from typing import Any

from app.database.connection import DatabaseManager

logger = logging.getLogger("rasp.repository.chat")


class ChatRepository:
    """Repository for ``security_chat_history`` table operations.

    Parameters
    ----------
    db : DatabaseManager
        The shared database manager instance.
    """

    def __init__(self, db: DatabaseManager) -> None:
        """Initialise with a DatabaseManager."""
        self._db = db

    async def save_message(
        self,
        session_id: str,
        role: str,
        message: str,
        device_id: str | None = None,
        user_id: int | None = None,
        token_count: int = 0,
    ) -> int:
        """Persist a single chat message.

        Parameters
        ----------
        session_id : str
            Chat session identifier.
        role : str
            One of ``"user"``, ``"assistant"``, or ``"system"``.
        message : str
            Message body text.
        device_id : str | None
            Optional device identifier.
        user_id : int | None
            Optional FK to ``users`` table.
        token_count : int
            Approximate token count for the message.

        Returns
        -------
        int
            Primary key of the inserted row.
        """
        message_id = await self._db.execute_write(
            """
            INSERT INTO security_chat_history (
                session_id, device_id, user_id, role, message, token_count
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, device_id, user_id, role, message, token_count),
        )
        logger.debug(
            "Saved chat message  id=%d  session=%s  role=%s",
            message_id, session_id, role,
        )
        return message_id

    async def get_session_history(
        self,
        session_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieve the most recent messages for a chat session.

        Returns messages in chronological order (oldest first) so they
        can be directly fed into the LLM context window.

        Parameters
        ----------
        session_id : str
            Chat session identifier.
        limit : int
            Maximum number of messages to retrieve.

        Returns
        -------
        list[dict]
            Message dictionaries with ``role``, ``message``, and
            ``created_at`` keys (oldest first).
        """
        return await self._db.execute_query(
            """
            SELECT id, role, message, token_count, created_at
            FROM security_chat_history
            WHERE session_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (session_id, limit),
        )

    async def delete_session(self, session_id: str) -> int:
        """Delete all messages for a given session.

        Parameters
        ----------
        session_id : str
            Chat session identifier to purge.

        Returns
        -------
        int
            Number of deleted rows (reported via lastrowid — may be 0
            for DELETE statements; use the return as a success signal).
        """
        result = await self._db.execute_write(
            "DELETE FROM security_chat_history WHERE session_id = ?",
            (session_id,),
        )
        logger.info("Deleted chat session  session_id=%s", session_id)
        return result
