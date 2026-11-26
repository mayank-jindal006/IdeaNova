from __future__ import annotations

import re
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .models import Finding


def _redact_from_secret(source_line: str, secret: str) -> str:
    if not source_line or not secret:
        return source_line
    candidate = secret.strip()
    if not candidate or candidate == "[REDACTED]":
        return source_line
    if candidate in source_line:
        return source_line.replace(candidate, "[REDACTED]", 1)
    return source_line


def redact_source_line(source_line: str, finding: "Finding") -> str:
    """Replace the secret region using the scanner's StartColumn/EndColumn values."""
    if not source_line:
        return source_line

    if finding.start_column is not None and finding.end_column is not None:
        start = max(0, finding.start_column - 1)
        end = min(len(source_line), max(start, finding.end_column))
        if end > start:
            return f"{source_line[:start]}[REDACTED]{source_line[end:]}"

    secret = finding.secret or finding.match
    return _redact_from_secret(source_line, secret or "")


def redact_content_for_llm(content: str, secrets: Iterable[str]) -> str:
    """Sanitize prompt content so Gemini never receives raw secrets."""
    if not content:
        return content

    cleaned_secrets = []
    for secret in secrets or ():
        candidate = (secret or "").strip()
        if candidate and candidate != "[REDACTED]":
            cleaned_secrets.append(candidate)

    sanitized = content
    for secret in sorted(set(cleaned_secrets), key=len, reverse=True):
        sanitized = sanitized.replace(secret, "[REDACTED]")

    return sanitized


# Defense in depth: source context may contain another credential unrelated to the finding.
_CONTEXT_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|pwd)\s*[=:]\s*[\"']?)[^\s\"']{8,}"),
)


def redact_context_for_llm(content: str, secrets: Iterable[str]) -> str:
    """Remove known and recognizable secret values before constructing an AI prompt."""
    sanitized = redact_content_for_llm(content, secrets)
    for pattern in _CONTEXT_SECRET_PATTERNS:
        if pattern.groups:
            sanitized = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", sanitized)
        else:
            sanitized = pattern.sub("[REDACTED]", sanitized)
    return sanitized
