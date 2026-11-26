from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ContractModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class RepoCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]+$")
    default_branch: str | None = Field(default=None, max_length=255)


class AuthCredentials(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=256)


class UserOut(ContractModel):
    id: int
    email: str
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class ScanRepositoryRequest(BaseModel):
    """Compatibility scan request bound to an owned persisted repository."""

    repo_id: int = Field(gt=0)


class ExplainFindingRequest(BaseModel):
    """Untrusted finding data and optional source context for AI explanation."""

    finding: dict
    source_context: str = Field(default="", max_length=20_000)


class RepoOut(ContractModel):
    id: int
    full_name: str
    default_branch: str
    created_at: datetime
    last_scanned_at: datetime | None


class ScanOut(ContractModel):
    id: int
    repo_id: int
    trigger: Literal["manual", "push", "pull_request"]
    commit_sha: str | None
    status: Literal["queued", "running", "done", "failed"]
    scanner_status: dict | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class FindingOut(ContractModel):
    id: int
    repo_id: int
    type: Literal["secret", "dependency"]
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"] | None
    scanner: str
    file_path: str | None
    line: int | None
    commit_sha: str | None
    secret_masked: str | None
    package: str | None
    ecosystem: str | None
    installed_version: str | None
    affected_versions: str | None
    fixed_version: str | None
    advisory_id: str | None
    aliases: list[str]
    references: list[str]
    cvss_score: float | None
    in_history_only: bool
    confidence: float
    status: Literal["open", "fix_proposed", "pr_opened", "fixed", "false_positive", "needs_rotation"]
    owasp_ids: list[str]
    asvs_ids: list[str]


class FixExplanation(BaseModel):
    what: str
    why_dangerous: str
    how_fixed: str
    rotation_required: bool
    rotation_note: str


class FixEdit(BaseModel):
    file_path: str
    new_content: str


class FixValidation(BaseModel):
    secret_removed: bool
    syntax_ok: bool
    notes: list[str]


class FixOut(BaseModel):
    finding_id: int
    explanation: FixExplanation
    edits: list[FixEdit]
    tier: Literal["auto_branch", "pr_review", "flag_only"]
    validation: FixValidation


class OpenPrOut(BaseModel):
    pr_url: str
    pr_number: int


class ScanQueuedOut(BaseModel):
    scan_id: int
    status: Literal["queued"]


class ScanHistoryOut(ScanOut):
    findings_count: int = 0


class FeedbackCreate(BaseModel):
    verdict: Literal["true_positive", "false_positive"]
    note: str | None = None
