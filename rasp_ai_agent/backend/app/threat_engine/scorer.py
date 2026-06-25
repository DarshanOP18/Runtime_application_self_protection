"""
app/threat_engine/scorer.py
────────────────────────────
Configurable threat scoring engine for RASP security signals.

The scorer consumes a flat dictionary of boolean threat flags, computes a
weighted raw score, applies combination multipliers when dangerous threat
pairs/triples are detected, and returns a rich ``ThreatAssessment`` dataclass.

Scoring Reference Table
-----------------------
.. list-table::
   :header-rows: 1

   * - Threats
     - Raw Score
     - Multiplier
     - Final
     - Level
   * - root only
     - 50
     - 1.0
     - 50
     - MEDIUM
   * - frida only
     - 80
     - 1.0
     - 80
     - MEDIUM
   * - root + frida
     - 130
     - 1.3
     - 169
     - CRITICAL
   * - root + frida + tamper
     - 190
     - 1.5
     - 285
     - CRITICAL
   * - vpn only
     - 15
     - 1.0
     - 15
     - LOW
   * - vpn + proxy
     - 35
     - 1.0
     - 35
     - LOW
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from app.config import get_settings


# ═══════════════════════════════════════════════════════════════════════
# Data Transfer Object
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ThreatAssessment:
    """Result produced by :py:meth:`ThreatScorer.calculate`.

    Attributes
    ----------
    score : int
        Final risk score after combination multipliers.
    level : str
        Human-readable risk level (LOW / MEDIUM / HIGH / CRITICAL).
    active_threats : list[str]
        Names of threats that were flagged ``True``.
    score_breakdown : dict[str, int]
        Individual score contributions, e.g. ``{"root_detected": 50}``.
    combination_bonus : int
        Additional points added by combination multipliers.
    summary : str
        Auto-generated plain-English summary (no LLM required).
    """

    score: int = 0
    level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    active_threats: list[str] = field(default_factory=list)
    score_breakdown: dict[str, int] = field(default_factory=dict)
    combination_bonus: int = 0
    summary: str = ""


# ═══════════════════════════════════════════════════════════════════════
# Threat Scorer
# ═══════════════════════════════════════════════════════════════════════

class ThreatScorer:
    """Configurable, deterministic threat scoring engine.

    All base scores are loaded from :py:class:`app.config.Settings` so they
    can be tuned via environment variables without code changes.

    Parameters
    ----------
    settings : Settings | None
        Optional override; when ``None`` the global singleton is used.
    """

    # ── Risk thresholds (inclusive ranges) ─────────────────────────────
    RISK_THRESHOLDS: dict[str, tuple[int, int]] = {
        "LOW":      (0,   49),
        "MEDIUM":   (50,  99),
        "HIGH":     (100, 149),
        "CRITICAL": (150, 9999),
    }

    def __init__(self, settings=None) -> None:
        """Initialise the scorer with base scores from configuration.

        Parameters
        ----------
        settings : Settings | None
            Pydantic settings instance.  Uses the global singleton when
            not provided.
        """
        s = settings or get_settings()

        self._base_scores: dict[str, int] = {
            "root_detected":        s.THREAT_SCORE_ROOT,
            "frida_detected":       s.THREAT_SCORE_FRIDA,
            "debugger_detected":    s.THREAT_SCORE_DEBUGGER,
            "tamper_detected":      s.THREAT_SCORE_TAMPER,
            "emulator_detected":    s.THREAT_SCORE_EMULATOR,
            "vpn_detected":         s.THREAT_SCORE_VPN,
            "proxy_detected":       s.THREAT_SCORE_PROXY,
            "overlay_detected":     s.THREAT_SCORE_OVERLAY,
            "accessibility_abuse":  s.THREAT_SCORE_ACCESSIBILITY,
            "hook_detected":        s.THREAT_SCORE_HOOK,
            "location_spoof":       s.THREAT_SCORE_LOCATION_SPOOF,
            "time_spoof":           s.THREAT_SCORE_TIME_SPOOF,
            "malware_detected":     s.THREAT_SCORE_MALWARE,
            "screenshot_detected":  s.THREAT_SCORE_SCREENSHOT,
        }

    # ── Public API ────────────────────────────────────────────────────

    def calculate(self, threat_payload: dict) -> ThreatAssessment:
        """Score a threat payload and produce a full assessment.

        Parameters
        ----------
        threat_payload : dict
            Flat dictionary whose keys are threat signal names and values
            are booleans (or ints 0/1).

        Returns
        -------
        ThreatAssessment
            Fully populated assessment with score, level, breakdown,
            active threats, combination bonus, and plain-English summary.
        """
        active_threats: list[str] = []
        score_breakdown: dict[str, int] = {}
        raw_score = 0

        # ── Sum base scores for active threats ────────────────────────
        for threat_name, base_score in self._base_scores.items():
            value = threat_payload.get(threat_name, False)
            if value and value not in (0, False):
                active_threats.append(threat_name)
                score_breakdown[threat_name] = base_score
                raw_score += base_score

        # ── Compute combination multiplier ────────────────────────────
        multiplier = self._get_combination_multiplier(active_threats)
        final_score = int(raw_score * multiplier)
        combination_bonus = final_score - raw_score

        # ── Determine risk level ──────────────────────────────────────
        level = self._score_to_level(final_score)

        # ── Build plain-English summary ───────────────────────────────
        summary = self._build_summary(active_threats, final_score, level)

        return ThreatAssessment(
            score=final_score,
            level=level,
            active_threats=active_threats,
            score_breakdown=score_breakdown,
            combination_bonus=combination_bonus,
            summary=summary,
        )

    # ── Private helpers ───────────────────────────────────────────────

    def _get_combination_multiplier(self, active: list[str]) -> float:
        """Return the highest applicable combination multiplier.

        Multiplier rules (highest wins):
        - root + frida + tamper → 1.5
        - frida + hook          → 1.4
        - root + frida          → 1.3
        - malware + any_other   → 1.3
        - root + tamper         → 1.2

        Parameters
        ----------
        active : list[str]
            List of active threat names.

        Returns
        -------
        float
            The highest multiplier that applies (≥ 1.0).
        """
        threat_set = set(active)
        multiplier = 1.0

        # Check in descending order of severity
        if {"root_detected", "frida_detected", "tamper_detected"}.issubset(threat_set):
            multiplier = max(multiplier, 1.5)
        if {"frida_detected", "hook_detected"}.issubset(threat_set):
            multiplier = max(multiplier, 1.4)
        if {"root_detected", "frida_detected"}.issubset(threat_set):
            multiplier = max(multiplier, 1.3)
        if "malware_detected" in threat_set and len(threat_set) > 1:
            multiplier = max(multiplier, 1.3)
        if {"root_detected", "tamper_detected"}.issubset(threat_set):
            multiplier = max(multiplier, 1.2)

        return multiplier

    def _score_to_level(self, score: int) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        """Map a numeric score to a risk level string.

        Parameters
        ----------
        score : int
            The computed risk score.

        Returns
        -------
        str
            One of LOW, MEDIUM, HIGH, CRITICAL.
        """
        for level, (low, high) in self.RISK_THRESHOLDS.items():
            if low <= score <= high:
                return level  # type: ignore[return-value]
        return "CRITICAL"

    def _build_summary(self, active: list[str], score: int, level: str) -> str:
        """Generate a human-readable summary without an LLM.

        Parameters
        ----------
        active : list[str]
            Active threat names.
        score : int
            Final risk score.
        level : str
            Risk level string.

        Returns
        -------
        str
            A plain-English sentence describing the assessment.
        """
        if not active:
            return "No security threats detected. The device appears to be in a safe state."

        threat_labels = [t.replace("_", " ").replace("detected", "").strip() for t in active]
        threat_str = ", ".join(threat_labels)
        return (
            f"Detected {len(active)} threat(s): {threat_str}. "
            f"Risk score: {score} ({level}). "
            f"{'Immediate action required.' if level in ('HIGH', 'CRITICAL') else 'Monitor the situation.'}"
        )
