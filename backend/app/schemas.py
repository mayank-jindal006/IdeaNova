from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ContractModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class RepoCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]+$")
    local_path: str | None = Field(default=None, min_length=1, max_length=4096)
    default_branch: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def exactly_one_source(self):
        if bool(self.full_name) == bool(self.local_path):
            raise ValueError("Specify exactly one repository source")
        return self


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
    source_type: Literal["local", "github"] = "github"
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
    description: str | None = None
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
    patch_syntax: Literal["passed", "failed", "not_run"] = "not_run"
    target_exists: bool | None = None
    tests: Literal["not_run", "passed", "failed"] = "not_run"
    security_rescan: Literal["not_run", "passed", "failed"] = "not_run"


class FixOut(BaseModel):
    id: int
    finding_id: int
    explanation: FixExplanation
    edits: list[FixEdit]
    tier: Literal["auto_branch", "pr_review", "flag_only"]
    validation: FixValidation
    patch: str | None = None
    target_file: str | None = None
    risk_level: Literal["low", "medium", "high", "critical"] | None = None
    model: str | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    status: Literal[
        "generated",
        "pending_review",
        "approved",
        "applied",
        "validation_passed",
        "validation_failed",
        "pr_opened",
        "merged",
        "rejected",
    ] = "generated"
    created_at: datetime | None = None


class FixReviewCreate(BaseModel):
    decision: Literal["approved", "rejected"]
    note: str | None = Field(default=None, max_length=2000)


class FixReviewOut(ContractModel):
    id: int
    fix_id: int
    reviewer_id: int | None
    reviewer_email: str
    decision: Literal["approved", "rejected"]
    note: str | None
    created_at: datetime


class AuditLogOut(ContractModel):
    id: int
    user_id: int | None
    actor_email: str | None
    repo_id: int | None
    finding_id: int | None
    fix_id: int | None
    action: str
    details: dict
    created_at: datetime


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
    note: str | None = Field(default=None, max_length=2000)
