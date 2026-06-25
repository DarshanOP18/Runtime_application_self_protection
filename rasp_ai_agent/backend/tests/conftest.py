"""
tests/conftest.py
─────────────────
Shared pytest fixtures for the RASP Security AI Backend test suite.

Provides:
- An in-memory SQLite database with migrations applied.
- Mock fixtures for the local LLM client using AsyncMock.
- A configured FastAPI ``TestClient`` / ``httpx.AsyncClient``.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ── Ensure test settings before any app imports ───────────────────────
os.environ["DATABASE_PATH"] = ":memory:"
os.environ["MIGRATIONS_DIR"] = "./migrations"
os.environ["OLLAMA_BASE_URL"] = "http://127.0.0.1:11434"
os.environ["OLLAMA_MODEL"] = "qwen2.5:7b"
os.environ["OLLAMA_NUM_GPU"] = "999"

from app.ai.local_llm_client import LocalLLMClient
from app.ai.security_analyst import SecurityAnalystAI
from app.api.security_router import set_dependencies
from app.database.connection import DatabaseManager
from app.main import create_app
from app.threat_engine.scorer import ThreatScorer

# ═══════════════════════════════════════════════════════════════════════
# Mock Local LLM Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def mock_llm_client() -> MagicMock:
    """Return a mock LocalLLMClient using AsyncMock.

    Always returns a valid threat explanation JSON or specialized mock output.
    """
    client = MagicMock(spec=LocalLLMClient)

    def generate_side_effect(*args, **kwargs) -> str:
        prompt = kwargs.get("prompt") or kwargs.get("user_prompt")
        if not prompt and len(args) > 1:
            prompt = args[1]
        elif not prompt and len(args) > 0:
            prompt = args[0]
        
        prompt_str = str(prompt).lower() if prompt else ""

        if "remediation" in prompt_str:
            return (
                '{"steps": [{"step_number": 1, "action": "Remove threat", '
                '"description": "Uninstall suspicious apps.", "difficulty": "easy"}], '
                '"estimated_time": "5 minutes", '
                '"requires_technical_knowledge": false, "priority": "HIGH"}'
            )
        if "follow-up" in prompt_str or "suggest" in prompt_str:
            return '["How can I protect my device?", "What is RASP?", "Is my data safe?"]'
        if "active threats" in prompt_str or "security threats" in prompt_str:
            return (
                '{"title": "Test Threat", '
                '"explanation": "Test explanation.", '
                '"technical_detail": "Test technical detail.", '
                '"recommendation": ["Step 1", "Step 2"], '
                '"severity_reason": "Test reason."}'
            )
        
        return (
            '{\n'
            '  "title": "Test Threat",\n'
            '  "explanation": "Test explanation.",\n'
            '  "technical_detail": "Test technical detail.",\n'
            '  "recommendation": ["Step 1", "Step 2"],\n'
            '  "severity_reason": "Test reason."\n'
            '}'
        )

    client.generate = AsyncMock(side_effect=generate_side_effect)
    client.chat = AsyncMock(return_value="This is a test AI response.")
    client.check_health = AsyncMock(return_value=True)
    client.close = AsyncMock()
    return client


@pytest.fixture
def mock_llm_chat() -> AsyncMock:
    """Mock LocalLLMClient.chat() specifically."""
    return AsyncMock(return_value="This is a test AI response.")


@pytest.fixture
def mock_llm_health_ok() -> AsyncMock:
    """Mock LocalLLMClient.check_health() to return True."""
    return AsyncMock(return_value=True)


@pytest.fixture
def mock_llm_health_fail() -> AsyncMock:
    """Mock LocalLLMClient.check_health() to return False."""
    return AsyncMock(return_value=False)


# ═══════════════════════════════════════════════════════════════════════
# Database Fixture
# ═══════════════════════════════════════════════════════════════════════

@pytest_asyncio.fixture
async def test_db() -> AsyncGenerator[DatabaseManager, None]:
    """Create an in-memory database with all migrations applied.

    Yields
    ------
    DatabaseManager
        A database manager connected to ``:memory:``.
    """
    db = DatabaseManager(db_path=":memory:", migrations_dir="./migrations")

    # Create the existing Flutter tables that migrations expect (users FK).
    conn = await db.get_connection()
    await conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, email TEXT, password_hash TEXT,
            contact_number TEXT, role_id INTEGER,
            is_verified INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1,
            login_count INTEGER DEFAULT 0, last_login_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        """
    )
    await conn.commit()

    # Run project migrations
    await db.run_migrations()

    try:
        yield db
    finally:
        await db.close()


# ═══════════════════════════════════════════════════════════════════════
# Client Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest_asyncio.fixture
async def test_client(test_db: DatabaseManager, mock_llm_client: MagicMock) -> AsyncGenerator[AsyncClient, None]:
    """Create an httpx AsyncClient pointed at the FastAPI test app with mock local LLM client.

    Yields
    ------
    AsyncClient
        An async HTTP client for making test requests.
    """
    analyst = SecurityAnalystAI(llm_client=mock_llm_client)
    scorer = ThreatScorer()

    set_dependencies(db=test_db, llm=mock_llm_client, analyst=analyst, scorer=scorer)
    app = create_app()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture
async def async_client(test_client: AsyncClient) -> AsyncGenerator[AsyncClient, None]:
    """Alias for compatibility with existing tests.

    Yields
    ------
    AsyncClient
        The configured test client.
    """
    yield test_client
