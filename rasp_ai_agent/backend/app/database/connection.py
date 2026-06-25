"""
app/database/connection.py
──────────────────────────
Async SQLite database manager using ``aiosqlite``.

Provides:
- Connection pooling via an async context manager.
- Automatic migration runner that tracks applied scripts in a
  ``schema_migrations`` table.
- Generic ``execute_query`` (SELECT) and ``execute_write`` (INSERT/UPDATE/
  DELETE) helpers that return Python dicts.
- Health check for the /health endpoint.

Supports both file-based and ``:memory:`` databases.  In-memory databases
use a single persistent connection so that tables and data survive across
calls (each ``aiosqlite.connect(":memory:")`` would otherwise create
a separate, empty database).

All interactions are fully async — no blocking I/O on the event loop.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import aiosqlite

from app.config import get_settings

logger = logging.getLogger("rasp.database")


class DatabaseManager:
    """Async SQLite database manager with migration support.

    Parameters
    ----------
    db_path : str | None
        Path to the SQLite file.  Uses ``Settings.DATABASE_PATH`` when
        ``None``.  Pass ``":memory:"`` for an in-memory database (useful
        for testing).
    migrations_dir : str | None
        Directory containing numbered ``.sql`` migration scripts.
    """

    def __init__(
        self,
        db_path: str | None = None,
        migrations_dir: str | None = None,
    ) -> None:
        """Initialise the manager with paths from config or overrides."""
        settings = get_settings()
        self._db_path = db_path or settings.DATABASE_PATH
        self._migrations_dir = migrations_dir or settings.MIGRATIONS_DIR
        self._is_memory = self._db_path == ":memory:"

        # Persistent connection for in-memory databases
        self._shared_conn: aiosqlite.Connection | None = None

        # Ensure the data directory exists (skip for in-memory)
        if not self._is_memory:
            os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)

    # ── Connection management ─────────────────────────────────────────

    async def get_connection(self) -> aiosqlite.Connection:
        """Open and return an aiosqlite connection.

        For file-based databases the caller is responsible for closing
        the connection after use.  For ``:memory:`` databases a shared
        persistent connection is returned — callers should **not** close
        it (closing is a no-op wrapper to keep the API uniform).

        Returns
        -------
        aiosqlite.Connection
            An open async SQLite connection with FK enforcement.
        """
        if self._is_memory:
            if self._shared_conn is None:
                self._shared_conn = await aiosqlite.connect(":memory:")
                self._shared_conn.row_factory = aiosqlite.Row
                await self._shared_conn.execute("PRAGMA foreign_keys=ON")
            return self._shared_conn

        conn = await aiosqlite.connect(self._db_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        return conn

    async def _release(self, conn: aiosqlite.Connection) -> None:
        """Release a connection after use.

        For file-based databases the connection is closed.  For
        ``:memory:`` databases the connection is kept open.

        Parameters
        ----------
        conn : aiosqlite.Connection
            The connection to release.
        """
        if not self._is_memory:
            await conn.close()

    async def close(self) -> None:
        """Close the persistent in-memory database connection, if open."""
        if self._shared_conn is not None:
            await self._shared_conn.close()
            self._shared_conn = None

    # ── Migration runner ──────────────────────────────────────────────

    async def run_migrations(self) -> list[str]:
        """Execute pending SQL migration scripts in numeric order.

        Tracks applied migrations in a ``schema_migrations`` table to
        ensure idempotency.

        Returns
        -------
        list[str]
            Names of newly applied migration files.

        Raises
        ------
        FileNotFoundError
            When the migrations directory does not exist.
        """
        migrations_path = Path(self._migrations_dir)
        if not migrations_path.exists():
            logger.warning("Migrations directory not found: %s", self._migrations_dir)
            return []

        conn = await self.get_connection()
        try:
            # Create tracking table if it doesn't exist
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename    TEXT NOT NULL UNIQUE,
                    applied_at  TEXT DEFAULT (datetime('now'))
                )
                """
            )
            await conn.commit()

            # Fetch already-applied migrations
            cursor = await conn.execute("SELECT filename FROM schema_migrations")
            applied = {row[0] for row in await cursor.fetchall()}

            # Discover and sort migration files
            sql_files = sorted(
                f for f in migrations_path.iterdir()
                if f.suffix == ".sql" and f.name not in applied
            )

            applied_now: list[str] = []
            for sql_file in sql_files:
                logger.info("Applying migration: %s", sql_file.name)
                sql = sql_file.read_text(encoding="utf-8")
                await conn.executescript(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (filename) VALUES (?)",
                    (sql_file.name,),
                )
                await conn.commit()
                applied_now.append(sql_file.name)
                logger.info("Migration applied: %s", sql_file.name)

            return applied_now
        finally:
            await self._release(conn)

    # ── Query helpers ─────────────────────────────────────────────────

    async def execute_query(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] = (),
    ) -> list[dict[str, Any]]:
        """Execute a SELECT query and return rows as dictionaries.

        Parameters
        ----------
        sql : str
            SQL SELECT statement (parameterised).
        params : tuple | dict
            Bind parameters.

        Returns
        -------
        list[dict[str, Any]]
            List of row dictionaries.
        """
        conn = await self.get_connection()
        try:
            cursor = await conn.execute(sql, params)
            columns = [description[0] for description in cursor.description] if cursor.description else []
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]
        finally:
            await self._release(conn)

    async def execute_write(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] = (),
    ) -> int:
        """Execute an INSERT, UPDATE, or DELETE and return the last row id.

        Parameters
        ----------
        sql : str
            SQL write statement (parameterised).
        params : tuple | dict
            Bind parameters.

        Returns
        -------
        int
            ``lastrowid`` for INSERT, or number of affected rows for
            UPDATE/DELETE.
        """
        conn = await self.get_connection()
        try:
            cursor = await conn.execute(sql, params)
            await conn.commit()
            return cursor.lastrowid or 0
        finally:
            await self._release(conn)

    # ── Health check ──────────────────────────────────────────────────

    async def check_health(self) -> bool:
        """Verify that the SQLite database is accessible.

        Returns
        -------
        bool
            ``True`` if a simple query succeeds, ``False`` otherwise.
        """
        try:
            conn = await self.get_connection()
            try:
                await conn.execute("SELECT 1")
                return True
            finally:
                await self._release(conn)
        except Exception as exc:
            logger.error("Database health check failed: %s", exc)
            return False


# ── Module-level migration runner (python -m app.database.connection) ─

async def _run_migrations_cli() -> None:
    """CLI entry point for running migrations."""
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    db = DatabaseManager()
    applied = await db.run_migrations()
    if applied:
        print(f"Applied {len(applied)} migration(s): {', '.join(applied)}")
    else:
        print("No new migrations to apply.")
    sys.exit(0)


if __name__ == "__main__":
    import asyncio
    asyncio.run(_run_migrations_cli())
