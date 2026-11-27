"""
LLM client for RepoGuard.
Every AI feature (explain, fix) calls complete_json() from this file.
"""
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from app.settings import settings


GUIDANCE_RESPONSE_SCHEMA = {
    "type": "object",
    "required": [
        "summary",
        "risk_assessment",
        "remediation",
        "developer_summary",
        "requires_rotation",
        "confidence",
    ],
    "properties": {
        "summary": {"type": "string"},
        "risk_assessment": {"type": "string"},
        "remediation": {"type": "string"},
        "developer_summary": {"type": "string"},
        "requires_rotation": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "additionalProperties": False,
}


class LLMError(Exception):
    """Raised when the LLM cannot give us a usable answer."""

    def __init__(self, message: str, *, category: str = "provider_error", status_code: int | None = None):
        super().__init__(message)
        self.category = category
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None


def _token_count(usage: Any, *names: str) -> int | None:
    if usage is None:
        return None
    for name in names:
        value = usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _call_gemini(system: str, user: str, response_schema: dict[str, Any]) -> ProviderResponse:
    from google import genai
    from google.genai import types

    client = genai.Client(
        api_key=settings.llm_api_key,
        http_options=types.HttpOptions(timeout=int(settings.llm_timeout_seconds * 1000)),  # milliseconds
    )
    response = client.models.generate_content(
        model=settings.llm_model,
        contents=user,
        config=types.GenerateContentConfig(
            system_instruction=system,
            temperature=0.1,
            response_mime_type="application/json",
            response_json_schema=response_schema,
        ),
    )
    usage = getattr(response, "usage_metadata", None)
    return ProviderResponse(
        text=response.text or "",
        input_tokens=_token_count(usage, "prompt_token_count", "promptTokenCount"),
        output_tokens=_token_count(usage, "candidates_token_count", "candidatesTokenCount"),
    )


def _call_openai_compatible(system: str, user: str, _response_schema: dict[str, Any]) -> ProviderResponse:
    """Used for the Groq backup (and OpenAI if ever needed)."""
    from openai import OpenAI

    client = OpenAI(api_key=settings.llm_api_key, base_url=settings.llm_base_url, timeout=settings.llm_timeout_seconds)
    response = client.chat.completions.create(
        model=settings.llm_model,
        temperature=0.1,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    usage = getattr(response, "usage", None)
    return ProviderResponse(
        text=response.choices[0].message.content or "",
        input_tokens=_token_count(usage, "prompt_tokens"),
        output_tokens=_token_count(usage, "completion_tokens"),
    )


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


def _status_code(error: Exception) -> int | None:
    """Extract a status code when a provider SDK exposes one, without logging its body."""
    for attribute in ("status_code", "code"):
        value = getattr(error, attribute, None)
        if isinstance(value, int):
            return value
    return None


def _provider_error_category(error: Exception) -> tuple[str, int | None]:
    """Classify provider failures into safe, UI-facing categories.

    Provider messages can include request details, so callers deliberately log only the
    returned category/status metadata rather than the exception text.
    """
    status_code = _status_code(error)
    if status_code in {401, 403}:
        return "authentication_or_permission", status_code
    if status_code == 404:
        return "model_or_endpoint", status_code
    if status_code == 429:
        return "rate_limited", status_code
    if status_code in {408, 504} or isinstance(error, TimeoutError):
        return "timeout", status_code

    error_type = type(error).__name__.lower()
    if "timeout" in error_type:
        return "timeout", status_code
    if any(marker in error_type for marker in ("connect", "connection", "network")):
        return "network_or_connection", status_code
    return "provider_error", status_code



def complete_json_with_metadata(
    system: str,
    user: str,
    retries: int = 2,
    response_schema: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], ProviderResponse]:
    """Return structured output and provider usage metadata without logging prompts."""
    if not settings.llm_api_key or not settings.llm_model:
        raise LLMError("LLM provider configuration is missing", category="missing_configuration")

    caller = _CALLERS.get(settings.llm_provider)
    if caller is None:
        raise LLMError("LLM provider is not supported", category="invalid_provider")

    schema = response_schema or GUIDANCE_RESPONSE_SCHEMA
    last_error = None
    last_category = "provider_error"
    last_status_code = None
    last_response = ProviderResponse("")
    for attempt in range(retries + 1):
        try:
            raw = caller(system, user, schema)
            last_response = raw if isinstance(raw, ProviderResponse) else ProviderResponse(str(raw))
            return extract_json(last_response.text), last_response
        except json.JSONDecodeError as e:
            last_error = e
            last_category = "malformed_response"
            user = user + "\n\nYour previous reply was not valid JSON. Reply with ONLY one JSON object."
        except Exception as e:
            last_error = e
            last_category, last_status_code = _provider_error_category(e)
            if attempt == retries:
                break
            wait = 15 if last_category == "rate_limited" else 2 * (attempt + 1)
            time.sleep(wait)

    raise LLMError(
        "LLM provider did not return usable guidance",
        category=last_category,
        status_code=last_status_code,
    ) from last_error


def complete_json(system: str, user: str, retries: int = 2) -> dict:
    """Ask the configured provider for a validated JSON object."""
    result, _ = complete_json_with_metadata(system, user, retries)
    return result


__all__ = [
    "GUIDANCE_RESPONSE_SCHEMA",
    "LLMError",
    "ProviderResponse",
    "complete_json",
    "complete_json_with_metadata",
]
