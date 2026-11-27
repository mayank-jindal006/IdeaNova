from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import AuditLog, Repo, User


def record_audit_event(
    db: Session,
    user: User | None,
    action: str,
    *,
    repo_id: int | None = None,
    finding_id: int | None = None,
    fix_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    event = AuditLog(
        user_id=user.id if user else None,
        actor_email=user.email if user else None,
        repo_id=repo_id,
        finding_id=finding_id,
        fix_id=fix_id,
        action=action,
        details=details or {},
    )
    db.add(event)
    return event


def list_owned_audit_events(db: Session, user: User, limit: int, offset: int) -> list[AuditLog]:
    owned_repo_ids = select(Repo.id).where(Repo.owner_id == user.id)
    return db.scalars(
        select(AuditLog)
        .where(or_(AuditLog.user_id == user.id, AuditLog.repo_id.in_(owned_repo_ids)))
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
