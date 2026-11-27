from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth import current_user
from app.db.models import User
from app.db.session import get_db
from app.schemas import AuditLogOut
from app.services.audit import list_owned_audit_events

router = APIRouter(tags=["audit"])


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> list:
    return list_owned_audit_events(db, user, limit, offset)
