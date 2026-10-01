"""Persistence boundary used by the self-healing agent."""

from sqlalchemy.orm import Session

from app.models import AgentRun


def record_agent_run(
    db: Session,
    repo_id: int,
    finding_id: int | None = None,
    fix_id: int | None = None,
    step: str = "",
    status: str = "",
    detail: str = "",
    attempt: int = 0,
) -> AgentRun:
    """Add an agent event to the caller's transaction without committing it."""
    run = AgentRun(
        repo_id=repo_id,
        finding_id=finding_id,
        fix_id=fix_id,
        step=step,
        status=status,
        detail=detail,
        attempt=attempt,
    )
    db.add(run)
    return run
