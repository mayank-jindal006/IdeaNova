from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.repos import _score_dict
from app.db.models import Finding, FindingStatus, Repo, RepoScore, User
from app.auth import current_user
from app.db.session import get_db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict:
    findings = db.scalars(select(Finding).join(Repo).where(Repo.owner_id == user.id)).all()
    active = [finding for finding in findings if finding.status not in {FindingStatus.fixed, FindingStatus.false_positive}]
    scores = []
    for repo in db.scalars(select(Repo).where(Repo.owner_id == user.id).order_by(Repo.id)).all():
        score = db.scalar(select(RepoScore).where(RepoScore.repo_id == repo.id).order_by(RepoScore.computed_at.desc()).limit(1))
        scores.append({"repo_id": repo.id, "full_name": repo.full_name, "latest_score": _score_dict(score)})
    start = datetime.now(timezone.utc) - timedelta(days=6)
    trend = [{"date": (start + timedelta(days=offset)).date().isoformat(), "findings": 0} for offset in range(7)]
    for finding in findings:
        created_at = finding.created_at
        if created_at and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at and created_at >= start:
            day = created_at.date().isoformat()
            for item in trend:
                if item["date"] == day:
                    item["findings"] += 1
    return {"totals": {"repos": len(scores), "open_findings": len(active), "critical_findings": sum(1 for finding in active if finding.severity and finding.severity.value == "critical"), "fixed_findings": sum(1 for finding in findings if finding.status == FindingStatus.fixed)}, "severity_counts": {severity: sum(1 for finding in active if finding.severity and finding.severity.value == severity) for severity in ("critical", "high", "medium", "low")}, "per_repo_scores": scores, "trend": trend}
