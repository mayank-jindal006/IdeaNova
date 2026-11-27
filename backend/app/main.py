from __future__ import annotations

import logging

from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.router import api_router
from app.routers import findings as compatibility_findings, repositories as compatibility_repositories
from app.settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def _error(code: str, message: str, status_code: int, request_id: str | None = None) -> JSONResponse:
    error = {"code": code, "message": message}
    if request_id:
        error["request_id"] = request_id
    response = JSONResponse(status_code=status_code, content={"error": error})
    if request_id:
        response.headers["X-Request-ID"] = request_id
    return response


def create_app() -> FastAPI:
    app = FastAPI(title="RepoGuard API", version="1.0.0", description="RepoGuard prototype API. OpenAPI documentation is served at /docs.")
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Authorization", "X-Hub-Signature-256"])
    app.include_router(api_router)
    # Keep the original synchronous scanner/explainer contract available to the
    # browser client while the database-backed API continues under /api/repos.
    app.include_router(compatibility_repositories.router)
    app.include_router(compatibility_findings.router)

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        request.state.request_id = request.headers.get("X-Request-ID") or str(uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/database")
    def database_health() -> dict[str, str]:
        from app.db.session import engine
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:
            raise HTTPException(status_code=503, detail="Database is unavailable") from None
        return {"status": "ok"}

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code = {401: "WEBHOOK_SIGNATURE_INVALID", 404: "NOT_FOUND", 409: "CONFLICT", 503: "SERVICE_UNAVAILABLE"}.get(exc.status_code, "REQUEST_FAILED")
        return _error(code, str(exc.detail), exc.status_code, request.state.request_id)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, __: RequestValidationError) -> JSONResponse:
        return _error("VALIDATION_ERROR", "Request validation failed", 422, request.state.request_id)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logging.getLogger("repoguard").exception("Unhandled application error")
        return _error("INTERNAL_ERROR", "An internal error occurred", 500, request.state.request_id)
    return app


app = create_app()
