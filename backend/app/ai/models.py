from __future__ import annotations

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class Finding(BaseModel):
    """Normalized finding from a secret or dependency security scanner."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    file: str | None = Field(default=None, validation_alias=AliasChoices("file", "File", "path", "Path"))
    line: int | None = Field(default=None, validation_alias=AliasChoices("line", "Line"))
    description: str | None = Field(
        default=None,
        validation_alias=AliasChoices("description", "Description"),
    )
    secret: str | None = Field(default=None, validation_alias=AliasChoices("secret", "Secret"))
    match: str | None = Field(default=None, validation_alias=AliasChoices("match", "Match"))
    rule_id: str | None = Field(default=None, validation_alias=AliasChoices("rule_id", "RuleID"))
    severity: str | None = Field(default=None, validation_alias=AliasChoices("severity", "Severity"))
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
    type: str | None = None
    scanner: str | None = None
    package: str | None = None
    ecosystem: str | None = None
    installed_version: str | None = None
    affected_versions: str | None = None
    fixed_version: str | None = None
    advisory_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    cvss_score: float | None = None

    @property
    def is_dependency(self) -> bool:
        return self.type == "dependency" or (
            self.scanner == "osv" and self.package is not None
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
