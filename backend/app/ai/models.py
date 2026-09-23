from __future__ import annotations

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class Finding(BaseModel):
    """Normalized representation of a secret finding from a security scanner."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    file: str | None = None
    line: int | None = None
    description: str | None = None
    secret: str | None = None
    match: str | None = None
    rule_id: str | None = Field(default=None, validation_alias=AliasChoices("rule_id", "RuleID"))
    severity: str | None = None
    start_line: int | None = Field(default=None, validation_alias=AliasChoices("start_line", "StartLine"))
    end_line: int | None = Field(default=None, validation_alias=AliasChoices("end_line", "EndLine"))
    start_column: int | None = Field(
        default=None,
        validation_alias=AliasChoices("start_column", "StartColumn"),
    )
    end_column: int | None = Field(
        default=None,
        validation_alias=AliasChoices("end_column", "EndColumn"),
    )

    def redact_source_line(self, source_line: str) -> str:
        from .redaction import redact_source_line

        return redact_source_line(source_line, self)

    def redacted(self) -> "Finding":
        redacted = self.model_copy(deep=True)
        if redacted.secret is not None:
            redacted.secret = "[REDACTED]"
        if redacted.match is not None:
            redacted.match = "[REDACTED]"
        return redacted
