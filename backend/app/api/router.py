from fastapi import APIRouter

from app.api import audit, auth, dashboard, findings, fixes, repos, scans, webhooks

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(repos.router)
api_router.include_router(findings.router)
api_router.include_router(fixes.router)
api_router.include_router(dashboard.router)
api_router.include_router(scans.router)
api_router.include_router(webhooks.router)
api_router.include_router(audit.router)
