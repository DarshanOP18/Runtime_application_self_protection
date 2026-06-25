"""
app/database/migrate.py
───────────────────────
CLI entry point for running database migrations.

Usage::

    python -m app.database.migrate

Reads migration SQL files from the ``migrations/`` directory and applies
them in numeric order, tracking applied scripts in the ``schema_migrations``
table to ensure idempotency.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from app.database.connection import DatabaseManager


async def main() -> None:
    """Run pending database migrations and exit.

    Prints the names of applied migrations to stdout.  Exits with code 0
    on success, 1 on failure.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)-8s %(message)s",
    )
    logger = logging.getLogger("rasp.migrate")

    try:
        db = DatabaseManager()
        applied = await db.run_migrations()

        if applied:
            logger.info("Applied %d migration(s):", len(applied))
            for name in applied:
                logger.info("  ✔ %s", name)
        else:
            logger.info("Database is up to date — no new migrations.")

        sys.exit(0)

    except Exception as exc:
        logger.error("Migration failed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
