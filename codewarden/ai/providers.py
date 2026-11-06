"""LLM provider adapters implemented with the Python standard library only.

Supported: Anthropic Claude, OpenAI, Google Gemini, Groq, OpenRouter, any
OpenAI-compatible endpoint (LM Studio, vLLM...), and local Ollama.
"""
from __future__ import annotations

import json
import os
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5-5",
    "openai": "gpt-4.1-mini",
    "gemini": "gemini-flash-latest",
    "groq": "llama-3.3-70b-versatile",
    "openrouter": "openrouter/auto",
    "ollama": "qwen2.5-coder:7b",
    "openai-compatible": "local-model",
}
KEY_ENV = {
    "anthropic": ["ANTHROPIC_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
    "groq": ["GROQ_API_KEY"],
    "openrouter": ["OPENROUTER_API_KEY"],
    "openai-compatible": ["OPENAI_COMPATIBLE_API_KEY"],
    "ollama": [],
}
PROVIDERS = list(DEFAULT_MODELS)
AUTO_ORDER = ["anthropic", "openai", "gemini", "groq", "openrouter"]


class ProviderError(Exception):
    pass


def env_key(provider: str) -> Optional[str]:
    for name in KEY_ENV.get(provider, []):
        v = os.environ.get(name, "").strip()
        if v:
            return v
    return None


def detect_provider() -> Optional[str]:
    explicit = os.environ.get("CODEWARDEN_PROVIDER", "").strip().lower()
    if explicit:
        return explicit
    for p in AUTO_ORDER:
        if env_key(p):
            return p
    return None


def extract_json(text: str) -> Dict:
    """Parse a JSON object from model output, tolerating fences and chatter."""
    if not text:
        raise ValueError("empty model response")
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    start = t.find("{")
    end = t.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object found in model response")
    body = t[start:end + 1]
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        body = re.sub(r",\s*([}\]])", r"\1", body)  # trailing commas
        return json.loads(body)


@dataclass
class LLMClient:
    provider: str
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    timeout: int = 240
    max_retries: int = 5
    temperature: float = 0.0

    @classmethod
    def create(cls, provider: str, model: Optional[str] = None, api_key: Optional[str] = None) -> "LLMClient":
        provider = provider.lower()
        if provider not in DEFAULT_MODELS:
            raise ProviderError(f"Unknown provider '{provider}'. Choose one of: {', '.join(PROVIDERS)}")
        model = model or os.environ.get("CODEWARDEN_MODEL") or DEFAULT_MODELS[provider]
        key = api_key or env_key(provider)
        if provider not in ("ollama", "openai-compatible") and not key:
            raise ProviderError(f"No API key for {provider}. Set {' or '.join(KEY_ENV[provider])} "
                                "(e.g. in a .env file) or pass it in the web UI.")
        base = None
        if provider == "ollama":
            base = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        elif provider == "openai":
            base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        elif provider == "groq":
            base = "https://api.groq.com/openai/v1"
        elif provider == "openrouter":
            base = "https://openrouter.ai/api/v1"
        elif provider == "openai-compatible":
            base = os.environ.get("OPENAI_COMPATIBLE_BASE_URL", "http://localhost:1234/v1").rstrip("/")
        return cls(provider, model, key, base)

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"

    # ------------------------------------------------------------------ public
    def complete(self, system: str, user: str, max_tokens: int = 8000) -> str:
        last_err = None
        use_temp = True
        for attempt in range(self.max_retries):
            try:
                return self._dispatch(system, user, max_tokens, use_temp)
            except _Retryable as exc:
                last_err = exc
                wait = exc.retry_after or min(60.0, (2 ** attempt) * 2 + random.random())
                time.sleep(wait)
            except _BadParam as exc:
                if use_temp:
                    use_temp = False  # some models reject temperature; retry without it
                    last_err = exc
                    continue
                raise ProviderError(str(exc)) from None
        raise ProviderError(f"{self.label} failed after {self.max_retries} attempts: {last_err}")

    # ---------------------------------------------------------------- internal
    def _dispatch(self, system, user, max_tokens, use_temp) -> str:
        if self.provider == "anthropic":
            body = {"model": self.model, "max_tokens": max_tokens, "system": system,
                    "messages": [{"role": "user", "content": user}]}
            if use_temp:
                body["temperature"] = self.temperature
            data = self._post("https://api.anthropic.com/v1/messages", body, {
                "x-api-key": self.api_key, "anthropic-version": "2023-06-01"})
            return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        if self.provider == "gemini":
            body = {"systemInstruction": {"parts": [{"text": system}]},
                    "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "generationConfig": {"responseMimeType": "application/json", "maxOutputTokens": max(max_tokens, 16384)}}
            if use_temp:
                body["generationConfig"]["temperature"] = self.temperature
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            data = self._post(url, body, {"x-goog-api-key": self.api_key})
            cands = data.get("candidates") or []
            if not cands:
                raise ProviderError(f"Gemini returned no candidates: {str(data.get('promptFeedback', ''))[:200]}")
            parts = cands[0].get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if self.provider == "ollama":
            body = {"model": self.model, "stream": False, "format": "json",
                    "options": {"temperature": self.temperature, "num_ctx": 32768},
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
            data = self._post(f"{self.base_url}/api/chat", body, {})
            return data.get("message", {}).get("content", "")
        # OpenAI and compatible (groq, openrouter, lm studio ...)
        body = {"model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object"}}
        if self.provider == "openai":
            body["max_completion_tokens"] = max_tokens
        else:
            body["max_tokens"] = max_tokens
        if use_temp:
            body["temperature"] = self.temperature
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        if self.provider == "openrouter":
            headers.update({"HTTP-Referer": "https://github.com/codewarden-ai", "X-Title": "CodeWarden AI"})
        data = self._post(f"{self.base_url}/chat/completions", body, headers)
        choices = data.get("choices") or []
        if not choices:
            raise ProviderError("model returned no choices")
        return choices[0].get("message", {}).get("content") or ""

    def _post(self, url: str, body: Dict, headers: Dict) -> Dict:
        payload = json.dumps(body).encode("utf-8")
        h = {"Content-Type": "application/json", "User-Agent": "codewarden-ai/1.0"}
        h.update({k: v for k, v in headers.items() if v})
        req = urllib.request.Request(url, data=payload, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = _safe_detail(exc)
            if exc.code in (408, 409, 425, 429, 500, 502, 503, 504, 529):
                ra = exc.headers.get("retry-after") if exc.headers else None
                raise _Retryable(f"HTTP {exc.code}: {detail}", float(ra) if ra and ra.replace('.', '', 1).isdigit() else None)
            if exc.code == 400 and "temperature" in detail.lower():
                raise _BadParam(detail)
            if exc.code in (401, 403):
                raise ProviderError(f"{self.provider} rejected the API key (HTTP {exc.code}). {detail}") from None
            if exc.code == 404:
                raise ProviderError(f"Model '{self.model}' not found for {self.provider} (HTTP 404). "
                                    "Set CODEWARDEN_MODEL to a model your account can use.") from None
            raise ProviderError(f"{self.provider} HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise _Retryable(f"network error: {exc.reason}", None)
        except TimeoutError:
            raise _Retryable("request timed out", None)


class _Retryable(Exception):
    def __init__(self, msg, retry_after):
        super().__init__(msg)
        self.retry_after = retry_after


class _BadParam(Exception):
    pass


def _safe_detail(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        msg = data.get("error", {})
        if isinstance(msg, dict):
            msg = msg.get("message", raw)
        return str(msg)[:300]
    except Exception:
        return ""


def check_provider(client: LLMClient) -> Tuple[bool, str]:
    """Tiny connectivity test used by `codewarden doctor`."""
    try:
        out = client.complete("Reply with JSON only.", 'Return {"ok": true}', max_tokens=50)
        extract_json(out)
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
