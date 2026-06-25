"""
Async Ollama client for the local Qwen model.

The backend talks to Ollama on the same machine and uses qwen2.5:7b by
default. No external LLM service or API key is required.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger("rasp.ai.local_llm")


class LocalLLMUnavailableError(Exception):
    """Raised when the local Ollama service cannot be reached."""

    def __init__(self, message: str = "Local LLM service is unavailable") -> None:
        self.message = message
        super().__init__(self.message)


class LocalLLMClient:
    """Async client for a local Ollama model."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            settings = get_settings()
            self._client = httpx.AsyncClient(
                base_url=settings.OLLAMA_BASE_URL.rstrip("/"),
                timeout=settings.OLLAMA_TIMEOUT,
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _options(self, temperature: float, max_tokens: int | None) -> dict[str, Any]:
        settings = get_settings()
        options: dict[str, Any] = {
            "temperature": temperature,
            "num_predict": max_tokens or settings.OLLAMA_MAX_TOKENS,
        }
        if settings.OLLAMA_NUM_GPU is not None:
            options["num_gpu"] = settings.OLLAMA_NUM_GPU
        return options

    async def generate(
        self,
        system_prompt: str | None = None,
        user_prompt: str | None = None,
        temperature: float = 0.3,
        prompt: str | None = None,
        system: str | None = None,
        max_tokens: int | None = None,
    ) -> str:
        final_system = system_prompt or system or ""
        final_user = user_prompt or prompt or ""

        messages: list[dict[str, str]] = []
        if final_system:
            messages.append({"role": "system", "content": final_system})
        if final_user:
            messages.append({"role": "user", "content": final_user})

        return await self.chat(messages=messages, temperature=temperature, max_tokens=max_tokens)

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.5,
        max_tokens: int | None = None,
    ) -> str:
        settings = get_settings()
        last_exception: Exception | None = None

        payload = {
            "model": settings.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "keep_alive": settings.OLLAMA_KEEP_ALIVE,
            "options": self._options(temperature, max_tokens),
        }

        for attempt in range(1, settings.OLLAMA_MAX_RETRIES + 1):
            try:
                logger.info(
                    "Local LLM request attempt %d/%d  model=%s  gpu_layers=%s",
                    attempt,
                    settings.OLLAMA_MAX_RETRIES,
                    settings.OLLAMA_MODEL,
                    settings.OLLAMA_NUM_GPU,
                )
                response = await self._get_client().post("/api/chat", json=payload)
                response.raise_for_status()
                data = response.json()
                generated_text = data.get("message", {}).get("content")
                if not generated_text:
                    raise ValueError("Ollama returned an empty response")

                logger.info("Local LLM response received  model=%s", settings.OLLAMA_MODEL)
                return str(generated_text).strip()

            except (httpx.HTTPError, ValueError) as exc:
                last_exception = exc
                logger.warning(
                    "Local LLM request failed (attempt %d/%d): %s",
                    attempt,
                    settings.OLLAMA_MAX_RETRIES,
                    exc,
                )
                if attempt < settings.OLLAMA_MAX_RETRIES:
                    await asyncio.sleep(2.0)

        raise LocalLLMUnavailableError(
            f"Local LLM unavailable after {settings.OLLAMA_MAX_RETRIES} attempts. "
            f"Last error: {last_exception}"
        ) from last_exception

    async def check_health(self) -> bool:
        try:
            response = await self._get_client().post(
                "/api/chat",
                json={
                    "model": get_settings().OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": "ping"}],
                    "stream": False,
                    "keep_alive": get_settings().OLLAMA_KEEP_ALIVE,
                    "options": {"num_predict": 5, "num_gpu": get_settings().OLLAMA_NUM_GPU},
                },
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
            return bool(data.get("message", {}).get("content"))
        except Exception as exc:
            logger.debug("Local LLM health check failed: %s", exc)
            return False


local_llm_client = LocalLLMClient()
