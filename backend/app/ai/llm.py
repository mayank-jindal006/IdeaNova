"""
LLM client for RepoGuard.
Every AI feature (explain, fix) calls complete_json() from this file.
"""
import json
import os
import re
import time

from dotenv import load_dotenv

load_dotenv()

PROVIDER = os.getenv("LLM_PROVIDER", "gemini").lower()
MODEL = os.getenv("LLM_MODEL")
API_KEY = os.getenv("LLM_API_KEY")
BASE_URL = os.getenv("LLM_BASE_URL")  # only needed for the Groq backup
TIMEOUT = float(os.getenv("LLM_TIMEOUT", "60"))


class LLMError(Exception):
    """Raised when the LLM cannot give us a usable answer."""

    

def _call_gemini(system: str, user: str) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(
        api_key=API_KEY,
        http_options=types.HttpOptions(timeout=int(TIMEOUT * 1000)),  # milliseconds
    )
    response = client.models.generate_content(
        model=MODEL,
        contents=user,
        config=types.GenerateContentConfig(
            system_instruction=system,
            temperature=0.1,
            response_mime_type="application/json",
        ),
    )
    return response.text or ""


def _call_openai_compatible(system: str, user: str) -> str:
    """Used for the Groq backup (and OpenAI if ever needed)."""
    from openai import OpenAI

    client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=TIMEOUT)
    response = client.chat.completions.create(
        model=MODEL,
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



def complete_json(system: str, user: str, retries: int = 2) -> dict:
    """Ask the LLM and return its reply as a dict. Retries on bad JSON and network/rate-limit errors."""
    if not API_KEY or not MODEL:
        raise LLMError("LLM_API_KEY or LLM_MODEL is missing in backend/.env")

    caller = _CALLERS.get(PROVIDER)
    if caller is None:
        raise LLMError(f"Unknown LLM_PROVIDER '{PROVIDER}'. Use one of: {', '.join(_CALLERS)}")

    last_error = None
    for attempt in range(retries + 1):
        try:
            raw = caller(system, user)
            return extract_json(raw)
        except json.JSONDecodeError as e:
            last_error = e
            user = user + "\n\nYour previous reply was not valid JSON. Reply with ONLY one JSON object."
        except Exception as e:
            last_error = e
            if attempt == retries:
                break
            wait = 15 if _is_rate_limit(e) else 2 * (attempt + 1)
            time.sleep(wait)

    raise LLMError(f"LLM failed after {retries + 1} attempts: {last_error}")