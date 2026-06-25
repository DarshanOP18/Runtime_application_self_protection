"""
app/utils/input_sanitizer.py
─────────────────────────────
Input sanitisation utilities for the RASP Security AI Backend.

Provides string cleaning functions used before data is written to the
database or forwarded to the LLM.  The goal is defense-in-depth — even
though parameterised queries prevent SQL injection, we still strip
dangerous metacharacters at the application boundary.
"""

from __future__ import annotations

import html
import re


class InputSanitizer:
    """Static utility class for input validation and cleaning.

    All methods are stateless and can be called without instantiation.
    """

    # ── Characters that should never appear in user-controlled strings ─
    _SQL_META_CHARS = re.compile(r"[;'\"\-\-\/\*\\]")
    _HTML_TAG_RE = re.compile(r"<[^>]+>")
    _DEVICE_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]+$")

    @staticmethod
    def sanitize_string(value: str) -> str:
        """Strip SQL metacharacters from a string.

        This is a defense-in-depth measure; primary SQL injection
        prevention is handled by parameterised queries.

        Parameters
        ----------
        value : str
            Raw user input.

        Returns
        -------
        str
            Cleaned string with dangerous characters removed.
        """
        # Remove null bytes
        cleaned = value.replace("\x00", "")
        # Strip SQL metacharacters
        cleaned = InputSanitizer._SQL_META_CHARS.sub("", cleaned)
        return cleaned.strip()

    @staticmethod
    def validate_device_id(value: str) -> bool:
        """Check whether a device_id contains only safe characters.

        Parameters
        ----------
        value : str
            The device_id to validate.

        Returns
        -------
        bool
            ``True`` if the value matches ``[a-zA-Z0-9_-]+``.
        """
        if not value or len(value) > 128:
            return False
        return bool(InputSanitizer._DEVICE_ID_RE.match(value))

    @staticmethod
    def validate_message(value: str, max_length: int = 1000) -> str:
        """Clean a chat message by stripping HTML and enforcing length.

        Parameters
        ----------
        value : str
            Raw message text.
        max_length : int
            Maximum allowed length after cleaning.

        Returns
        -------
        str
            Sanitised, length-limited message.
        """
        # Strip HTML tags
        cleaned = InputSanitizer._HTML_TAG_RE.sub("", value)
        # Unescape HTML entities
        cleaned = html.unescape(cleaned)
        # Remove null bytes
        cleaned = cleaned.replace("\x00", "")
        # Truncate
        cleaned = cleaned[:max_length].strip()
        return cleaned
