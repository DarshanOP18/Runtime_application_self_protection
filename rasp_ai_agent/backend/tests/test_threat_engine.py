"""
tests/test_threat_engine.py
───────────────────────────
Unit tests for the ThreatScorer class.

Covers:
- Individual threat scoring (root, frida, vpn).
- No-threat baseline.
- All-threats maximum.
- Combination multiplier application.
- Score breakdown key consistency.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.threat_engine.scorer import ThreatScorer


@pytest.fixture
def scorer() -> ThreatScorer:
    """Return a ThreatScorer with default settings.

    Returns
    -------
    ThreatScorer
        Scorer initialised with default base scores.
    """
    return ThreatScorer(settings=Settings())


class TestThreatScorer:
    """Tests for ThreatScorer.calculate()."""

    def test_root_only_score(self, scorer: ThreatScorer) -> None:
        """Root-only → raw 50, no multiplier → score 50, MEDIUM."""
        result = scorer.calculate({"root_detected": True})
        assert result.score == 50
        assert result.level == "MEDIUM"
        assert "root_detected" in result.active_threats
        assert result.combination_bonus == 0

    def test_frida_only_score(self, scorer: ThreatScorer) -> None:
        """Frida-only → raw 80, no multiplier → score 80, MEDIUM."""
        result = scorer.calculate({"frida_detected": True})
        assert result.score == 80
        assert result.level == "MEDIUM"
        assert "frida_detected" in result.active_threats

    def test_root_frida_multiplier(self, scorer: ThreatScorer) -> None:
        """Root + Frida → raw 130, multiplier 1.3 → score 169, CRITICAL."""
        result = scorer.calculate({
            "root_detected": True,
            "frida_detected": True,
        })
        assert result.score == 169
        assert result.level == "CRITICAL"
        assert result.combination_bonus == 39  # 169 - 130

    def test_root_frida_tamper_multiplier(self, scorer: ThreatScorer) -> None:
        """Root + Frida + Tamper → raw 190, multiplier 1.5 → score 285, CRITICAL."""
        result = scorer.calculate({
            "root_detected": True,
            "frida_detected": True,
            "tamper_detected": True,
        })
        assert result.score == 285
        assert result.level == "CRITICAL"

    def test_no_threats(self, scorer: ThreatScorer) -> None:
        """No threats → score 0, level LOW."""
        result = scorer.calculate({})
        assert result.score == 0
        assert result.level == "LOW"
        assert result.active_threats == []
        assert result.score_breakdown == {}
        assert result.combination_bonus == 0

    def test_vpn_only(self, scorer: ThreatScorer) -> None:
        """VPN-only → raw 15, no multiplier → score 15, LOW."""
        result = scorer.calculate({"vpn_detected": True})
        assert result.score == 15
        assert result.level == "LOW"

    def test_vpn_proxy(self, scorer: ThreatScorer) -> None:
        """VPN + Proxy → raw 35, no multiplier → score 35, LOW."""
        result = scorer.calculate({
            "vpn_detected": True,
            "proxy_detected": True,
        })
        assert result.score == 35
        assert result.level == "LOW"

    def test_all_threats(self, scorer: ThreatScorer) -> None:
        """All threats active → CRITICAL risk level."""
        all_threats = {
            "root_detected": True,
            "frida_detected": True,
            "debugger_detected": True,
            "tamper_detected": True,
            "emulator_detected": True,
            "vpn_detected": True,
            "proxy_detected": True,
            "overlay_detected": True,
            "accessibility_abuse": True,
            "hook_detected": True,
            "location_spoof": True,
            "time_spoof": True,
            "malware_detected": True,
            "screenshot_detected": True,
        }
        result = scorer.calculate(all_threats)
        assert result.level == "CRITICAL"
        assert len(result.active_threats) == 14

    def test_combination_multiplier_application(self, scorer: ThreatScorer) -> None:
        """Frida + Hook → multiplier 1.4 is applied correctly."""
        result = scorer.calculate({
            "frida_detected": True,
            "hook_detected": True,
        })
        raw = 80 + 70  # 150
        expected = int(raw * 1.4)  # 210
        assert result.score == expected
        assert result.level == "CRITICAL"
        assert result.combination_bonus == expected - raw

    def test_malware_plus_other_multiplier(self, scorer: ThreatScorer) -> None:
        """Malware + VPN → multiplier 1.3 applied."""
        result = scorer.calculate({
            "malware_detected": True,
            "vpn_detected": True,
        })
        raw = 90 + 15  # 105
        expected = int(raw * 1.3)  # 136
        assert result.score == expected

    def test_root_tamper_multiplier(self, scorer: ThreatScorer) -> None:
        """Root + Tamper → multiplier 1.2 applied."""
        result = scorer.calculate({
            "root_detected": True,
            "tamper_detected": True,
        })
        raw = 50 + 60  # 110
        expected = int(raw * 1.2)  # 132
        assert result.score == expected

    def test_score_breakdown_keys_match_active_threats(self, scorer: ThreatScorer) -> None:
        """Score breakdown keys must exactly match active_threats list."""
        result = scorer.calculate({
            "root_detected": True,
            "vpn_detected": True,
            "screenshot_detected": True,
        })
        assert set(result.score_breakdown.keys()) == set(result.active_threats)
        assert result.score_breakdown["root_detected"] == 50
        assert result.score_breakdown["vpn_detected"] == 15
        assert result.score_breakdown["screenshot_detected"] == 10

    def test_summary_contains_threat_count(self, scorer: ThreatScorer) -> None:
        """Summary should mention the number of active threats."""
        result = scorer.calculate({
            "root_detected": True,
            "frida_detected": True,
        })
        assert "2 threat(s)" in result.summary

    def test_no_threat_summary(self, scorer: ThreatScorer) -> None:
        """No-threat summary should mention safe state."""
        result = scorer.calculate({})
        assert "No security threats" in result.summary

    def test_false_values_ignored(self, scorer: ThreatScorer) -> None:
        """Explicitly False or 0 values should not contribute to score."""
        result = scorer.calculate({
            "root_detected": False,
            "frida_detected": 0,
            "vpn_detected": True,
        })
        assert result.score == 15
        assert result.active_threats == ["vpn_detected"]
