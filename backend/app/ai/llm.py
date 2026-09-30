"""
LLM client for RepoGuard.
Every AI feature (explain, fix) calls complete_json() from this file.

Two providers, both configured in backend/.env:
  LLM_*           -> the main provider (Groq)
  LLM_FALLBACK_*  -> optional backup (Gemini). Used ONLY if the main provider fails,
                     e.g. it is down, rate-limited, or keeps returning broken JSON.
"""
import json
import logging
import os
import re
import time
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class LLMError(Exception):
    """Raised when the LLM cannot give us a usable answer."""


@dataclass(frozen=True)
class ProviderConfig:
    provider: str          # "groq" | "gemini" | "openai"
    model: str | None
    api_key: str | None
    base_url: str | None   # only for OpenAI-compatible APIs such as Groq
    timeout: float
    label: str             # "main" or "fallback", used in logs and error messages


def _config(prefix: str, label: str) -> ProviderConfig | None:
    """Read one provider's settings from the environment. None if it isn't configured at all."""
    provider = os.getenv(f"{prefix}PROVIDER")
    if not provider:
        return None
    return ProviderConfig(
        provider=provider.lower().strip(),
        model=os.getenv(f"{prefix}MODEL"),
        api_key=os.getenv(f"{prefix}API_KEY"),
        base_url=os.getenv(f"{prefix}BASE_URL") or None,
        timeout=float(os.getenv(f"{prefix}TIMEOUT") or os.getenv("LLM_TIMEOUT") or "60"),
        label=label,
    )


def _providers() -> list[ProviderConfig]:
    """Main provider first, then the fallback (if configured). Read on every call, so a
    changed .env value is picked up without editing code."""
    main = _config("LLM_", "main")
    fallback = _config("LLM_FALLBACK_", "fallback")
    if fallback and not fallback.api_key:
        fallback = None   # a fallback without a key can't help; don't cut the main provider's retries for it
    return [c for c in (main, fallback) if c]


def _call_gemini(cfg: ProviderConfig, system: str, user: str) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(
        api_key=cfg.api_key,
        http_options=types.HttpOptions(timeout=int(cfg.timeout * 1000)),  # milliseconds
    )
    response = client.models.generate_content(
        model=cfg.model,
        contents=user,
        config=types.GenerateContentConfig(
            system_instruction=system,
            temperature=0.1,
            response_mime_type="application/json",
        ),
    )
    return response.text or ""


def _call_openai_compatible(cfg: ProviderConfig, system: str, user: str) -> str:
    """Groq (and OpenAI) use the same request format."""
    from openai import OpenAI

    client = OpenAI(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)
    response = client.chat.completions.create(
        model=cfg.model,
        temperature=0.1,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return response.choices[0].message.content or ""


_CALLERS = {
    "gemini": _call_gemini,
    "groq": _call_openai_compatible,
    "openai": _call_openai_compatible,
}


def extract_json(text: str) -> dict:
    """Turn the model's reply into a Python dict, even if it added ``` fences or extra words."""
    text = re.sub(r"```(?:json)?", "", text).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        text = text[start:end + 1]
    data = json.loads(text)  # raises json.JSONDecodeError if it's still not valid JSON
    if not isinstance(data, dict):
        raise json.JSONDecodeError("Expected a JSON object", text, 0)
    return data


def _is_rate_limit(error: Exception) -> bool:
    """True if Google/Groq said 'too many requests' (HTTP 429)."""
    message = str(error)
    return getattr(error, "code", None) == 429 or "429" in message or "RESOURCE_EXHAUSTED" in message


def _ask(cfg: ProviderConfig, system: str, user: str, retries: int) -> dict:
    """Ask ONE provider, with retries. Raises LLMError if it can't produce a JSON object."""
    if not cfg.api_key or not cfg.model:
        raise LLMError(f"{cfg.label} provider: API key or model is missing in backend/.env")
    caller = _CALLERS.get(cfg.provider)
    if caller is None:
        raise LLMError(f"{cfg.label} provider: unknown provider '{cfg.provider}'. Use one of: {', '.join(_CALLERS)}")

    last_error = None
    for attempt in range(retries + 1):
        try:
            return extract_json(caller(cfg, system, user))
        except json.JSONDecodeError as e:
            last_error = e
            user = user + "\n\nYour previous reply was not valid JSON. Reply with ONLY one JSON object."
        except Exception as e:  # network error, timeout, rate limit, provider outage
            last_error = e
            if attempt == retries:
                break
            wait = 15 if _is_rate_limit(e) else 2 * (attempt + 1)
            time.sleep(wait)
    raise LLMError(f"{cfg.label} provider ({cfg.provider}) failed after {retries + 1} attempts: {last_error}")


def complete_json(system: str, user: str, retries: int = 2) -> dict:
    """Ask the main provider; if it fails, ask the fallback. Returns the reply as a dict."""
    providers = _providers()
    if not providers:
        raise LLMError("No LLM configured: set LLM_PROVIDER, LLM_MODEL and LLM_API_KEY in backend/.env")

    # With a fallback available, don't make the user wait through many retries on a
    # provider that is already failing: one retry on main, then switch.
    main_retries = min(retries, 1) if len(providers) > 1 else retries

    errors = []
    for i, cfg in enumerate(providers):
        try:
            result = _ask(cfg, system, user, main_retries if i == 0 else retries)
            if i > 0:
                logger.warning("LLM main provider failed; answered by fallback (%s)", cfg.provider)
            return result
        except LLMError as e:
            errors.append(str(e))
            logger.warning("%s", e)
    raise LLMError(" | ".join(errors))