from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding


def redact_source_line(source_line: str, finding: "Finding") -> str:
    """Replace the secret region using the scanner's StartColumn/EndColumn values."""
    if not source_line:
        return source_line
    if finding.start_column is None or finding.end_column is None:
        return source_line

    start = max(0, finding.start_column - 1)
    end = min(len(source_line), max(start, finding.end_column))
    if end <= start:
        return source_line

    return f"{source_line[:start]}[REDACTED]{source_line[end:]}"
