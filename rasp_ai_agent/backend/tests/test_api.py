"""
tests/test_api.py
─────────────────
Integration tests for the RASP Security AI Backend REST API.

Uses ``httpx.AsyncClient`` with ``ASGITransport`` to test endpoints
against a real FastAPI app instance backed by an in-memory SQLite
database and a mock local LLM client.

All tests use fixtures from ``conftest.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.ai.local_llm_client import LocalLLMClient, LocalLLMUnavailableError
from app.ai.security_analyst import SecurityAnalystAI
from app.api.security_router import set_dependencies
from app.database.connection import DatabaseManager
from app.main import create_app
from app.threat_engine.scorer import ThreatScorer


@pytest.mark.asyncio
class TestHealthEndpoint:
    """Tests for GET /api/v1/security/health."""

    async def test_health_endpoint_returns_200(self, async_client: AsyncClient) -> None:
        """Health check should return 200 with status field."""
        response = await async_client.get("/api/v1/security/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
        assert data["agent_available"] is True
        assert data["agent_mode"] == "local_llm"
        assert data["database_connected"] is True
        assert data["llm_available"] is True
        assert "version" in data
        assert "uptime_seconds" in data
        assert data["model_loaded"] == "qwen2.5:7b"

    async def test_health_endpoint_reports_fallback_agent_online(
        self,
        test_db: DatabaseManager,
    ) -> None:
        """Health should stay online when the local LLM is down but fallbacks are ready."""
        mock_client = MagicMock(spec=LocalLLMClient)
        mock_client.check_health = AsyncMock(return_value=False)
        mock_client.generate = AsyncMock(side_effect=LocalLLMUnavailableError())
        mock_client.chat = AsyncMock(side_effect=LocalLLMUnavailableError())
        mock_client.close = AsyncMock()

        analyst = SecurityAnalystAI(llm_client=mock_client)
        scorer = ThreatScorer()
        set_dependencies(db=test_db, llm=mock_client, analyst=analyst, scorer=scorer)
        app = create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/api/v1/security/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["agent_available"] is True
        assert data["agent_mode"] == "fallback"
        assert data["llm_available"] is False
        assert data["database_connected"] is True


@pytest.mark.asyncio
class TestAnalyzeEndpoint:
    """Tests for POST /api/v1/security/analyze."""

    async def test_analyze_does_not_require_api_key(self, async_client: AsyncClient) -> None:
        """Analyze requests should be accepted without authentication headers."""
        response = await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": "TEST001", "root_detected": True},
        )
        assert response.status_code == 200

    async def test_analyze_root_returns_medium(self, async_client: AsyncClient) -> None:
        """Root-only should produce MEDIUM risk with score 50."""
        response = await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": "TEST001", "root_detected": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk"] == "MEDIUM"
        assert data["score"] == 50
        assert "root_detected" in data["active_threats"]
        assert data["device_id"] == "TEST001"
        assert data["threat_id"] > 0

    async def test_analyze_root_frida_returns_critical(self, async_client: AsyncClient) -> None:
        """Root + Frida should produce CRITICAL risk with score 169."""
        response = await async_client.post(
            "/api/v1/security/analyze",
            json={
                "device_id": "TEST002",
                "root_detected": True,
                "frida_detected": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk"] == "CRITICAL"
        assert data["score"] == 169
        assert "root_detected" in data["active_threats"]
        assert "frida_detected" in data["active_threats"]

    async def test_analyze_no_threats(self, async_client: AsyncClient) -> None:
        """No threats should produce LOW risk with score 0."""
        response = await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": "SAFE_DEVICE"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk"] == "LOW"
        assert data["score"] == 0

    async def test_invalid_device_id_rejected(self, async_client: AsyncClient) -> None:
        """Device ID with special characters should be rejected (422)."""
        response = await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": "bad device; DROP TABLE;"},
        )
        assert response.status_code == 422

    async def test_analyze_returns_remediation_steps(self, async_client: AsyncClient) -> None:
        """Analysis should include remediation_steps list."""
        response = await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": "TEST_REMED", "malware_detected": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["remediation_steps"], list)
        assert len(data["remediation_steps"]) > 0

    async def test_analyze_response_structure(self, async_client: AsyncClient) -> None:
        """Verify all required fields are present in the response."""
        response = await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": "STRUCT_TEST", "vpn_detected": True},
        )
        assert response.status_code == 200
        data = response.json()
        required_fields = [
            "request_id", "device_id", "risk", "score",
            "score_breakdown", "active_threats", "title",
            "summary", "explanation", "technical_detail",
            "recommendation", "remediation_steps",
            "threat_id", "analyzed_at",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    async def test_local_llm_unavailable_returns_fallback(self, test_db: DatabaseManager) -> None:
        """When the local LLM is unavailable, threat explanation should fall back to rule-based response."""
        mock_client = MagicMock(spec=LocalLLMClient)
        mock_client.generate = AsyncMock(side_effect=LocalLLMUnavailableError("Local LLM down"))
        mock_client.check_health = AsyncMock(return_value=False)
        mock_client.close = AsyncMock()

        analyst = SecurityAnalystAI(llm_client=mock_client)
        scorer = ThreatScorer()
        set_dependencies(db=test_db, llm=mock_client, analyst=analyst, scorer=scorer)
        app = create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/api/v1/security/analyze",
                json={"device_id": "FALLBACK_TEST", "root_detected": True},
            )
            assert response.status_code == 200
            data = response.json()
            assert "Root/Jailbreak" in data["title"]
            assert "elevated privileges" in data["explanation"]
            assert len(data["remediation_steps"]) > 0


@pytest.mark.asyncio
class TestChatEndpoint:
    """Tests for POST /api/v1/security/chat."""

    async def test_chat_does_not_require_api_key(self, async_client: AsyncClient) -> None:
        """Chat requests should be accepted without authentication headers."""
        response = await async_client.post(
            "/api/v1/security/chat",
            json={"message": "What is Frida?", "session_id": "sess_001"},
        )
        assert response.status_code == 200

    async def test_chat_returns_response(self, async_client: AsyncClient) -> None:
        """Chat should return a response with suggested questions."""
        response = await async_client.post(
            "/api/v1/security/chat",
            json={"message": "What is Frida?", "session_id": "sess_001"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == "sess_001"
        assert len(data["response"]) > 0
        assert isinstance(data["suggested_questions"], list)
        assert len(data["suggested_questions"]) == 3
        assert "responded_at" in data
        assert data["message_id"] > 0


@pytest.mark.asyncio
class TestHistoryEndpoint:
    """Tests for GET /api/v1/security/history/{device_id}."""

    async def test_history_returns_list(self, async_client: AsyncClient) -> None:
        """History should return events list and metadata."""
        # First create a threat event
        await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": "HIST_DEVICE", "root_detected": True},
        )

        # Then fetch history
        response = await async_client.get(
            "/api/v1/security/history/HIST_DEVICE",
        )
        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == "HIST_DEVICE"
        assert data["total_events"] >= 1
        assert isinstance(data["events"], list)
        assert data["risk_trend"] in ("IMPROVING", "WORSENING", "STABLE")

    async def test_history_empty_device(self, async_client: AsyncClient) -> None:
        """History for unknown device should return empty events."""
        response = await async_client.get(
            "/api/v1/security/history/NONEXISTENT_DEVICE",
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_events"] == 0
        assert data["events"] == []

    async def test_history_invalid_device_id(self, async_client: AsyncClient) -> None:
        """History with invalid device_id format should return 400."""
        response = await async_client.get(
            "/api/v1/security/history/bad device!",
        )
        assert response.status_code == 400


@pytest.mark.asyncio
class TestDeleteChatEndpoint:
    """Tests for DELETE /api/v1/security/chat/{session_id}."""

    async def test_delete_chat_session(self, async_client: AsyncClient) -> None:
        """Should delete session and return confirmation."""
        # Create a chat message first
        await async_client.post(
            "/api/v1/security/chat",
            json={"message": "test msg", "session_id": "sess_del"},
        )

        # Delete session
        response = await async_client.delete(
            "/api/v1/security/chat/sess_del",
        )
        assert response.status_code == 200
        data = response.json()
        assert data["deleted"] is True
        assert data["session_id"] == "sess_del"


@pytest.mark.asyncio
class TestRateLimiting:
    """Tests for rate limiting behaviour."""

    async def test_rate_limit_enforced(self, async_client: AsyncClient) -> None:
        """Exceeding rate limit should return 429.

        Note: The analyze endpoint allows 30 req/min per device_id.
        We send 31 requests rapidly to trigger the limit.
        """
        device_id = "RATE_LIMIT_TEST"
        for i in range(30):
            resp = await async_client.post(
                "/api/v1/security/analyze",
                json={"device_id": device_id, "vpn_detected": True},
            )
            assert resp.status_code == 200, f"Request {i+1} failed with {resp.status_code}"

        # 31st request should be rate-limited
        resp = await async_client.post(
            "/api/v1/security/analyze",
            json={"device_id": device_id, "vpn_detected": True},
        )
        assert resp.status_code == 429
