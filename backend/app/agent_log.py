"""Persistence boundary used by the self-healing agent."""

from sqlalchemy.orm import Session

from app.models import AgentRun, AgentStep


def record_agent_run(
    db: Session,
    repo_id: int,
    step: AgentStep | str,
    detail: str | None,
    finding_id: int | None = None,
    fix_id: int | None = None,
    attempt: int = 0,
) -> AgentRun:
    """Add an agent event to the caller's transaction without committing it."""
    run = AgentRun(
        repo_id=repo_id,
        finding_id=finding_id,
        fix_id=fix_id,
        attempt=attempt,
        step=AgentStep(step),
        detail=detail,
    )
    db.add(run)
    return run
