from __future__ import annotations

import hashlib
import difflib
import os
import shutil
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.ai.fix import _safe_fallback, generate_fix, validate_target_path
from app.ai.models import Finding as AIFinding
from app.ai.redaction import redact_context_for_llm
from app.core.config import settings as config_settings
from app.core.scan_paths import ScanPathError, ScanRootError, require_scan_root, validate_scan_path
from app.db.models import AiRequestLog, Feedback, FeedbackVerdict, Finding, FindingStatus, FindingType, Fix, FixStatus, FixTier, Repo, User
from app.auth import current_user, owned_repo
from app.db.session import get_db
from app.schemas import FeedbackCreate, FindingOut, FixOut
from app.services.audit import record_audit_event
from app.services.ai_service import generate_security_recommendation_with_metadata
from app.services.gitleaks import scan_repository_secrets
from app.github_client.client import clone_repo
from app.risk.finding import assess_finding_risk
from app.settings import settings as runtime_settings
from app.services.local_remediation import requirements_candidate

router = APIRouter(tags=["findings"])


def _rotation_checklist(finding: Finding) -> list[str]:
    if finding.type.value != "secret":
        return []
    return ["Revoke the exposed credential.", "Create a replacement credential.", "Update the deployed environment with the replacement."]


def _read_finding_file(
    repo: Repo,
    file_path: str | None,
) -> tuple[str, str | None]:
    if not file_path:
        return "", None
    checkout_path: str | None = None
    try:
        relative = validate_target_path(file_path)
        require_scan_root()
        if repo.local_path:
            if os.getenv("REPOGUARD_LOCAL_SCAN_ENABLED", "").lower() != "true":
                return "", None
            checkout = validate_scan_path(repo.local_path)
            secret_scan = scan_repository_secrets(checkout, working_tree=True)
        else:
            checkout_path = clone_repo(repo.full_name)
            checkout = validate_scan_path(checkout_path)
            secret_scan = scan_repository_secrets(checkout)
        if secret_scan.source != "gitleaks" or secret_scan.status not in {"completed", "empty"}:
            return "", None
        target = (checkout / Path(*relative.split("/"))).resolve(strict=True)
        if not target.is_relative_to(checkout) or not target.is_file():
            return "", None
        if target.stat().st_size > 1_000_000:
            return "", None
        source_bytes = target.read_bytes()
        content = source_bytes.decode("utf-8")
        lines = content.splitlines(keepends=True)
        for secret_finding in secret_scan.findings:
            reported_path = Path(secret_finding.file)
            if reported_path.is_absolute():
                try:
                    reported_path = reported_path.resolve().relative_to(checkout)
                except (OSError, ValueError):
                    return "", None
            reported_name = reported_path.as_posix().removeprefix("./")
            if reported_name != relative:
                continue
            start_line = secret_finding.start_line or secret_finding.line
            end_line = secret_finding.end_line or start_line
            if start_line is None or end_line is None or start_line < 1 or end_line < start_line or end_line > len(lines):
                return "", None
            for index in range(max(start_line - 1, 0), min(end_line, len(lines))):
                line = lines[index]
                ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else "\r" if line.endswith("\r") else ""
                lines[index] = f"[REDACTED]{ending}"
        content = redact_context_for_llm("".join(lines), [])
        base_hash = hashlib.sha256(source_bytes).hexdigest()
    except (OSError, UnicodeDecodeError, ScanPathError, ScanRootError, ValueError, RuntimeError):
        return "", None
    finally:
        if checkout_path:
            shutil.rmtree(checkout_path, ignore_errors=True)
    return content, base_hash


def _finding_context(content: str, line: int | None) -> str:
    if line is None or line < 1:
        return content[: config_settings.max_source_context_chars]
    lines = content.splitlines()
    start = max(0, line - 21)
    end = min(len(lines), line + 20)
    return "\n".join(lines[start:end])[: config_settings.max_source_context_chars]


def _read_finding_source(repo: Repo, file_path: str | None, line: int | None = None) -> str:
    content, _ = _read_finding_file(repo, file_path)
    return _finding_context(content, line)


def _ai_finding(finding: Finding) -> AIFinding:
    payload = FindingOut.model_validate(finding).model_dump(mode="json")
    payload["file"] = payload.pop("file_path")
    return AIFinding.model_validate({key: value for key, value in payload.items() if key in AIFinding.model_fields})


@router.get("/repos/{repo_id}/findings", response_model=list[FindingOut])
def list_findings(
    repo_id: int,
    type: Literal["secret", "dependency"] | None = None,
    status: Literal["open", "fix_proposed", "pr_opened", "fixed", "false_positive", "needs_rotation"] | None = None,
    severity: Literal["critical", "high", "medium", "low"] | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: Literal["created_at", "severity", "status"] = "created_at",
    sort_order: Literal["asc", "desc"] = "desc",
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> list[Finding]:
    owned_repo(db, repo_id, user)
    if limit < 1 or limit > 200 or offset < 0:
        raise HTTPException(422, "Pagination parameters are invalid")
    query = select(Finding).join(Repo).where(Finding.repo_id == repo_id, Repo.owner_id == user.id)
    if type is not None:
        query = query.where(Finding.type == type)
    if status is not None:
        query = query.where(Finding.status == status)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    sort_column = {
        "created_at": Finding.created_at,
        "severity": Finding.severity,
        "status": Finding.status,
    }[sort_by]
    sort_expression = sort_column.desc() if sort_order == "desc" else sort_column.asc()
    return db.scalars(query.order_by(sort_expression, Finding.id.desc()).offset(offset).limit(limit)).all()


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    finding = db.scalar(select(Finding).join(Repo).where(Finding.id == finding_id, Repo.owner_id == user.id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    latest_fix = db.scalar(select(Fix).where(Fix.finding_id == finding_id).order_by(desc(Fix.created_at)).limit(1))
    fix = None
    if latest_fix:
        fix = {
            "id": latest_fix.id,
            "finding_id": finding_id,
            "explanation": latest_fix.explanation,
            "edits": latest_fix.edits,
            "patch": latest_fix.patch,
            "target_file": latest_fix.target_file,
            "risk_level": latest_fix.risk_level,
            "model": latest_fix.model,
            "tier": latest_fix.tier.value,
            "validation": latest_fix.validation,
            "status": latest_fix.status.value,
            "pr_url": latest_fix.pr_url,
            "pr_number": latest_fix.pr_number,
            "created_at": latest_fix.created_at,
        }
    return {
        "finding": FindingOut.model_validate(finding).model_dump(mode="json"),
        "fix": fix,
        "rotation_checklist": _rotation_checklist(finding),
        "risk_assessment": assess_finding_risk(FindingOut.model_validate(finding).model_dump(mode="json")),
    }


@router.post("/findings/{finding_id}/explain")
def explain_persisted_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict:
    finding = db.scalar(select(Finding).join(Repo).where(Finding.id == finding_id, Repo.owner_id == user.id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    repo = db.get(Repo, finding.repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")

    ai_finding = _ai_finding(finding)
    source_context = (
        ""
        if finding.type == FindingType.secret
        else _read_finding_source(repo, finding.file_path, finding.line)
    )
    explanation, usage = generate_security_recommendation_with_metadata(ai_finding, source_context)
    risk = assess_finding_risk(FindingOut.model_validate(finding).model_dump(mode="json"))
    ai_log = AiRequestLog(
        finding_id=finding.id,
        user_id=user.id,
        purpose="explanation",
        provider=runtime_settings.llm_provider,
        model=runtime_settings.llm_model,
        status="fallback" if explanation.get("guidance_source") == "rule_based_fallback" else "completed",
        failure_category=explanation.get("guidance_failure_reason"),
        input_tokens=usage.input_tokens if usage else None,
        output_tokens=usage.output_tokens if usage else None,
        result=explanation,
    )
    db.add(ai_log)
    record_audit_event(
        db,
        user,
        "ai.explanation_generated",
        repo_id=repo.id,
        finding_id=finding.id,
        details={"guidance_source": explanation.get("guidance_source", "unknown")},
    )
    db.commit()
    return {
        "finding": FindingOut.model_validate(finding).model_dump(mode="json"),
        "explanation": explanation,
        "risk_assessment": risk,
    }


@router.post("/findings/{finding_id}/fix", response_model=FixOut)
def create_fix(finding_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> FixOut:
    finding = db.scalar(select(Finding).join(Repo).where(Finding.id == finding_id, Repo.owner_id == user.id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    repo = db.get(Repo, finding.repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")
    finding_payload = FindingOut.model_validate(finding).model_dump(mode="json")
    source_content, base_hash = (
        ("", None)
        if finding.type == FindingType.secret
        else _read_finding_file(repo, finding.file_path)
    )
    expected_local = requirements_candidate(finding.file_path or "", source_content, finding_payload) if repo.local_path else None
    if repo.local_path and finding.type != FindingType.secret and expected_local is None:
        generated = _safe_fallback(finding_payload, "local_context_or_advisory_insufficient")
    else:
        if expected_local is not None:
            generated = generate_fix(finding_payload, finding.file_path or "", source_content, expected_content=expected_local)
        else:
            generated = generate_fix(finding_payload, finding.file_path or "", source_content)
    if repo.local_path and generated.get("patch") is not None:
        edits = generated.get("edits") or []
        model_content = edits[0].get("new_content") if len(edits) == 1 else None
        if expected_local is None or not isinstance(model_content, str) or model_content.replace("\r\n", "\n") != expected_local.replace("\r\n", "\n"):
            generated = _safe_fallback(finding_payload, "proposal_does_not_match_verified_advisory")
        else:
            # Preserve the source file's line endings when a provider normalizes CRLF to LF.
            edits[0]["new_content"] = expected_local
            generated["patch"] = "".join(difflib.unified_diff(
                source_content.splitlines(keepends=True), expected_local.splitlines(keepends=True),
                fromfile=f"a/{finding.file_path}", tofile=f"b/{finding.file_path}",
            ))
            generated["validation"]["notes"].append("Dependency compatibility has not been verified; review and run project tests.")
    if generated["patch"] is not None and base_hash is None:
        generated = {
            **generated,
            "edits": [],
            "patch": None,
            "target_file": None,
            "base_hash": None,
            "tier": "flag_only",
            "status": "generated",
            "validation": {
                **generated["validation"],
                "target_exists": False,
                "patch_syntax": "failed",
                "notes": ["The source file changed or could not be safely verified; no patch is available."],
            },
        }
    generated["base_hash"] = base_hash

    fix = Fix(
        finding_id=finding_id,
        explanation=generated["explanation"],
        edits=generated["edits"],
        patch=generated["patch"],
        target_file=generated["target_file"],
        base_hash=base_hash,
        risk_level=generated["risk_level"],
        model=generated["model"],
        tier=FixTier(generated["tier"]),
        validation=generated["validation"],
        status=FixStatus(generated["status"]),
    )
    db.add(fix)
    db.flush()
    usage = generated["usage"]
    db.add(AiRequestLog(
        finding_id=finding.id,
        user_id=user.id,
        purpose="remediation",
        provider=runtime_settings.llm_provider,
        model=runtime_settings.llm_model,
        status="failed" if generated["failure_category"] else "completed",
        failure_category=generated["failure_category"],
        input_tokens=usage.input_tokens if usage else None,
        output_tokens=usage.output_tokens if usage else None,
        result={
            "status": generated["status"],
            "target_file": generated["target_file"],
            "risk_level": generated["risk_level"],
        },
    ))
    if generated["patch"] is not None:
        finding.status = FindingStatus.fix_proposed
    record_audit_event(
        db,
        user,
        "fix.proposed",
        repo_id=repo.id,
        finding_id=finding.id,
        fix_id=fix.id,
        details={"status": generated["status"], "target_file": generated["target_file"]},
    )
    db.commit()
    db.refresh(fix)
    return FixOut.model_validate({
        "id": fix.id,
        **generated,
        "finding_id": finding_id,
        "base_hash": None,
        "created_at": fix.created_at,
    })


@router.post("/findings/{finding_id}/feedback", response_model=FindingOut)
def feedback(finding_id: int, payload: FeedbackCreate, db: Session = Depends(get_db), user: User = Depends(current_user)) -> Finding:
    finding = db.scalar(select(Finding).join(Repo).where(Finding.id == finding_id, Repo.owner_id == user.id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    db.add(Feedback(finding_id=finding_id, verdict=FeedbackVerdict(payload.verdict), note=payload.note))
    if payload.verdict == "false_positive":
        finding.status = FindingStatus.false_positive
    record_audit_event(
        db,
        user,
        "finding.feedback_recorded",
        repo_id=finding.repo_id,
        finding_id=finding.id,
        details={"verdict": payload.verdict},
    )
    db.commit()
    db.refresh(finding)
    return finding
