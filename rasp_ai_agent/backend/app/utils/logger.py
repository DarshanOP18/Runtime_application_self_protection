"""
app/utils/logger.py
───────────────────
Structured JSON logging for the RASP Security AI Backend.

Configures Python's ``logging`` module with:
- A **console handler** (INFO+ by default) that writes coloured,
  human-readable output during development.
- A **file handler** (DEBUG+) that writes one JSON object per line
  to ``./logs/rasp_backend.log``, rotated daily with 30-day retention.

Every log record is augmented with ``service``, ``request_id``, and
``device_id`` context fields.  Sensitive values (passwords, API keys,
session tokens) are masked with ``***``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from typing import Any


# ═══════════════════════════════════════════════════════════════════════
# Sensitive data masking
# ═══════════════════════════════════════════════════════════════════════

_SENSITIVE_KEYS = re.compile(
    r"(password|api[_\-]?key|secret|token|session_token|authorization)",
    re.IGNORECASE,
)


def _mask_sensitive(data: Any) -> Any:
    """Recursively mask values whose keys look sensitive.

    Parameters
    ----------
    data : Any
        The data structure to sanitise (dict, list, or scalar).

    Returns
    -------
    Any
        A copy with sensitive string values replaced by ``***``.
    """
    if isinstance(data, dict):
        return {
            k: "***" if isinstance(v, str) and _SENSITIVE_KEYS.search(k) else _mask_sensitive(v)
            for k, v in data.items()
        }
    if isinstance(data, (list, tuple)):
        return [_mask_sensitive(item) for item in data]
    return data


# ═══════════════════════════════════════════════════════════════════════
# JSON Formatter
# ═══════════════════════════════════════════════════════════════════════

class JSONFormatter(logging.Formatter):
    """Formats each log record as a single JSON line.

    Fields emitted:
    - ``timestamp`` (ISO 8601 UTC)
    - ``level``
    - ``service`` ("rasp-backend")
    - ``logger``
    - ``request_id`` (from ``record.request_id`` if set)
    - ``device_id`` (from ``record.device_id`` if set)
    - ``message``
    - ``extra`` (any additional key-value context)
    """

    def format(self, record: logging.LogRecord) -> str:
        """Convert a log record to a JSON string.

        Parameters
        ----------
        record : logging.LogRecord
            Standard Python log record.

        Returns
        -------
        str
            Single-line JSON string.
        """
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "rasp-backend",
            "logger": record.name,
            "request_id": getattr(record, "request_id", None),
            "device_id": getattr(record, "device_id", None),
            "message": record.getMessage(),
        }

        # Capture extra context
        extra_keys = set(record.__dict__) - set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) - {"request_id", "device_id"}
        if extra_keys:
            extra = {k: record.__dict__[k] for k in extra_keys if not k.startswith("_")}
            extra = _mask_sensitive(extra)
            if extra:
                log_entry["extra"] = extra

        # Include exception info if present
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════
# Console Formatter (human-readable)
# ═══════════════════════════════════════════════════════════════════════

class ConsoleFormatter(logging.Formatter):
    """Coloured, human-readable formatter for terminal output.

    Uses ANSI escape codes for level colouring.
    """

    _COLOURS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[1;31m", # Bold Red
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with colour and timestamp.

        Parameters
        ----------
        record : logging.LogRecord
            Standard Python log record.

        Returns
        -------
        str
            Formatted, coloured string.
        """
        colour = self._COLOURS.get(record.levelname, "")
        reset = self._RESET
        ts = datetime.now().strftime("%H:%M:%S")
        req_id = getattr(record, "request_id", None)
        prefix = f"[{req_id[:8]}] " if req_id else ""
        return f"{colour}{ts} {record.levelname:8s}{reset} {prefix}{record.name}: {record.getMessage()}"


# ═══════════════════════════════════════════════════════════════════════
# Setup function
# ═══════════════════════════════════════════════════════════════════════

def setup_logging(log_level: str = "INFO", log_dir: str = "./logs") -> None:
    """Configure application-wide logging.

    Parameters
    ----------
    log_level : str
        Minimum level for the console handler (e.g. ``"INFO"``).
    log_dir : str
        Directory for the rotating log file.  Created if it does not
        exist.
    """
    os.makedirs(log_dir, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # ── Remove existing handlers (prevents duplicates on reload) ──────
    root.handlers.clear()

    # ── Console handler ───────────────────────────────────────────────
    console = logging.StreamHandler()
    console.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    console.setFormatter(ConsoleFormatter())
    root.addHandler(console)

    # ── File handler (JSON, daily rotation, 30-day retention) ─────────
    log_file = os.path.join(log_dir, "rasp_backend.log")
    file_handler = TimedRotatingFileHandler(
        filename=log_file,
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())
    root.addHandler(file_handler)

    # ── Suppress noisy third-party loggers ────────────────────────────
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    logging.getLogger("rasp").info("Logging initialised  level=%s  file=%s", log_level, log_file)
