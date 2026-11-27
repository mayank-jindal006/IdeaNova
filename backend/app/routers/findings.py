from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.ai.models import Finding
from app.schemas import ExplainFindingRequest
from app.services.ai_service import generate_security_recommendation
from app.auth import current_user
from app.db.models import AiRequestLog, User
from app.db.session import get_db
from app.services.audit import record_audit_event
from app.settings import settings
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/findings", tags=["Findings"])
logger = logging.getLogger(__name__)


@router.post("/explain", summary="Generate a redaction-safe remediation explanation")
async def explain_finding(
    payload: ExplainFindingRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    try:
        finding = Finding.model_validate(payload.finding)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Finding payload is invalid") from exc

    explanation = await run_in_threadpool(generate_security_recommendation, finding, payload.source_context)
    logger.info(
        "Finding explanation completed guidance_source=%s failure_reason=%s",
        explanation.get("guidance_source", "unknown"),
        explanation.get("guidance_failure_reason", "none"),
    )
    db.add(AiRequestLog(
        user_id=user.id,
        purpose="compatibility_explanation",
        provider=settings.llm_provider,
        model=settings.llm_model,
        status="fallback" if explanation.get("guidance_source") == "rule_based_fallback" else "completed",
        failure_category=explanation.get("guidance_failure_reason"),
        result=explanation,
    ))
    record_audit_event(
        db,
        user,
        "ai.compatibility_explanation_generated",
        details={"guidance_source": explanation.get("guidance_source", "unknown")},
    )
    db.commit()
    return {"finding": finding.redacted().model_dump(mode="json", exclude_none=True), "explanation": explanation}
