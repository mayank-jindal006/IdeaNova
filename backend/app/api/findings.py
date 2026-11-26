from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.ai.fix import generate_fix
from app.db.models import Feedback, FeedbackVerdict, Finding, FindingStatus, Fix, FixStatus, Repo, User
from app.auth import current_user, owned_repo
from app.db.session import get_db
from app.schemas import FeedbackCreate, FindingOut, FixOut

router = APIRouter(tags=["findings"])


def _rotation_checklist(finding: Finding) -> list[str]:
    if finding.type.value != "secret":
        return []
    return ["Revoke the exposed credential.", "Create a replacement credential.", "Update the deployed environment with the replacement."]


@router.get("/repos/{repo_id}/findings", response_model=list[FindingOut])
def list_findings(repo_id: int, type: str | None = None, status: str | None = None, severity: str | None = None, db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[Finding]:
    owned_repo(db, repo_id, user)
    query = select(Finding).join(Repo).where(Finding.repo_id == repo_id, Repo.owner_id == user.id)
    if type is not None:
        query = query.where(Finding.type == type)
    if status is not None:
        query = query.where(Finding.status == status)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    return db.scalars(query.order_by(desc(Finding.created_at))).all()


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    finding = db.scalar(select(Finding).join(Repo).where(Finding.id == finding_id, Repo.owner_id == user.id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    latest_fix = db.scalar(select(Fix).where(Fix.finding_id == finding_id).order_by(desc(Fix.created_at)).limit(1))
    fix = None
    if latest_fix:
        fix = {"finding_id": finding_id, "explanation": latest_fix.explanation, "edits": latest_fix.edits, "tier": latest_fix.tier.value, "validation": latest_fix.validation}
    return {"finding": FindingOut.model_validate(finding).model_dump(mode="json"), "fix": fix, "rotation_checklist": _rotation_checklist(finding)}


@router.post("/findings/{finding_id}/fix", response_model=FixOut)
def create_fix(finding_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)) -> FixOut:
    finding = db.scalar(select(Finding).join(Repo).where(Finding.id == finding_id, Repo.owner_id == user.id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding_payload = FindingOut.model_validate(finding).model_dump(mode="json")
    generated = generate_fix(finding_payload, "", [])
    fix = Fix(finding_id=finding_id, explanation=generated["explanation"], edits=generated["edits"], tier=generated["tier"], validation=generated["validation"], status=FixStatus.generated)
    finding.status = FindingStatus.fix_proposed
    db.add(fix)
    db.commit()
    return FixOut.model_validate(generated)


@router.post("/findings/{finding_id}/feedback", response_model=FindingOut)
def feedback(finding_id: int, payload: FeedbackCreate, db: Session = Depends(get_db), user: User = Depends(current_user)) -> Finding:
    finding = db.scalar(select(Finding).join(Repo).where(Finding.id == finding_id, Repo.owner_id == user.id))
    if not finding:
        raise HTTPException(404, "Finding not found")
    db.add(Feedback(finding_id=finding_id, verdict=FeedbackVerdict(payload.verdict), note=payload.note))
    if payload.verdict == "false_positive":
        finding.status = FindingStatus.false_positive
    db.commit()
    db.refresh(finding)
    return finding
