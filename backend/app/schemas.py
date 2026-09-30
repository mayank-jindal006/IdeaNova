from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RepoCreate(BaseModel):
    full_name: str = Field(min_length=3, max_length=255)


class RepoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    full_name: str
    default_branch: str
    created_at: datetime
    last_scanned_at: datetime | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int | None = None
    repo_id: int
    type: Literal["secret", "dependency"]
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    file_path: str
    line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    commit_sha: str | None = None
    secret_masked: str | None = None
    package: str | None = None
    ecosystem: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    in_history_only: bool = False
    confidence: float = 1.0
    status: Literal["open", "fix_proposed", "pr_opened", "fixed", "false_positive", "needs_rotation"] = "open"
    owasp_ids: list[str] = Field(default_factory=list)
    asvs_ids: list[str] = Field(default_factory=list)


class ScanCreated(BaseModel):
    scan_id: int
    status: Literal["queued", "running", "done", "failed"]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    repo_id: int
    trigger: Literal["manual", "push", "pull_request"]
    commit_sha: str | None
    status: Literal["queued", "running", "done", "failed"]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class FixOut(BaseModel):
    id: int | None = None
    finding_id: int
    explanation: dict
    edits: list[dict]
    tier: Literal["auto_branch", "pr_review", "flag_only"]
    validation: dict


class FeedbackCreate(BaseModel):
    verdict: Literal["true_positive", "false_positive"]
    note: str | None = None


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
