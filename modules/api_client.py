"""
AI Red Team Scanner - API Client
=================================
Generischer Client für verschiedene LLM-APIs (OpenAI-kompatibel, Anthropic, etc.)
"""

import asyncio
import logging
import json
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    logger.warning("httpx nicht installiert - API-Tests nicht verfügbar")


@dataclass
class APIConfig:
    """API-Konfiguration für das Ziel-System"""
    base_url: str
    api_key: str = ""
    model: str = ""
    api_type: str = "openai"  # openai, anthropic, custom
    headers: dict = None
    system_prompt: str = ""  # Falls wir wissen welcher System Prompt gesetzt ist

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


class LLMAPIClient:
    """
    Generischer Client für LLM-APIs.
    Unterstützt OpenAI-kompatible APIs, Anthropic, und Custom Endpoints.
    """

    def __init__(self, config: APIConfig):
        self.config = config
        self.conversation_history = []

        if not HAS_HTTPX:
            raise ImportError("httpx benötigt: pip install httpx")

        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers=self._build_headers(),
        )

    def _build_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}

        if self.config.api_type == "openai":
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        elif self.config.api_type == "anthropic":
            headers["x-api-key"] = self.config.api_key
            headers["anthropic-version"] = "2023-06-01"

        headers.update(self.config.headers or {})
        return headers

    async def send_message(self, message: str, reset_history: bool = True) -> Optional[str]:
        """Nachricht an die API senden"""
        if reset_history:
            self.conversation_history = []

        self.conversation_history.append({"role": "user", "content": message})

        try:
            if self.config.api_type in ("openai", "custom"):
                return await self._send_openai(message)
            elif self.config.api_type == "anthropic":
                return await self._send_anthropic(message)
            else:
                return await self._send_generic(message)
        except Exception as e:
            logger.error(f"API-Fehler: {e}")
            return f"[ERROR] {str(e)}"

    async def _send_openai(self, message: str) -> Optional[str]:
        """OpenAI-kompatible API"""
        messages = []
        if self.config.system_prompt:
            messages.append({"role": "system", "content": self.config.system_prompt})
        messages.extend(self.conversation_history)

        payload = {
            "model": self.config.model or "gpt-4",
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 1000,
        }

        response = await self.client.post(
            f"{self.config.base_url}/chat/completions",
            json=payload,
        )
        response.raise_for_status()

        data = response.json()
        assistant_msg = data["choices"][0]["message"]["content"]
        self.conversation_history.append({"role": "assistant", "content": assistant_msg})
        return assistant_msg

    async def _send_anthropic(self, message: str) -> Optional[str]:
        """Anthropic API"""
        payload = {
            "model": self.config.model or "claude-sonnet-4-20250514",
            "max_tokens": 1000,
            "messages": self.conversation_history,
        }
        if self.config.system_prompt:
            payload["system"] = self.config.system_prompt

        response = await self.client.post(
            f"{self.config.base_url}/messages",
            json=payload,
        )
        response.raise_for_status()

        data = response.json()
        assistant_msg = data["content"][0]["text"]
        self.conversation_history.append({"role": "assistant", "content": assistant_msg})
        return assistant_msg

    async def _send_generic(self, message: str) -> Optional[str]:
        """Generischer HTTP-Endpoint"""
        payload = {
            "message": message,
            "history": self.conversation_history,
        }

        response = await self.client.post(
            self.config.base_url,
            json=payload,
        )
        response.raise_for_status()

        data = response.json()
        # Versuche verschiedene Response-Formate zu parsen
        for key in ["response", "message", "content", "text", "answer", "output"]:
            if key in data:
                assistant_msg = data[key]
                if isinstance(assistant_msg, str):
                    self.conversation_history.append({"role": "assistant", "content": assistant_msg})
                    return assistant_msg

        # Fallback: Gesamte Response als String
        return json.dumps(data)

    async def send_conversation(self, messages: list[str]) -> list[str]:
        """Mehrere Nachrichten als Konversation senden (ohne Reset)"""
        responses = []
        for i, msg in enumerate(messages):
            response = await self.send_message(msg, reset_history=(i == 0))
            responses.append(response or "")
            await asyncio.sleep(1)
        return responses

    async def close(self):
        """Client schließen"""
        await self.client.aclose()
