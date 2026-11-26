from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.router import api_router
from app.core.http import RequestSizeLimitMiddleware
from app.db.session import engine
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
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def create_app() -> FastAPI:
    production = settings.environment in {"production", "prod"}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        engine.dispose()

    app = FastAPI(
        title="RepoGuard API",
        version="1.0.0",
        description="RepoGuard API.",
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=settings.max_request_bytes)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-Hub-Signature-256"],
    )
    app.include_router(api_router)
    # Keep the original synchronous scanner/explainer contract available to the
    # browser client while the database-backed API continues under /api/repos.
    app.include_router(compatibility_repositories.router)
    app.include_router(compatibility_findings.router)

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        supplied_request_id = request.headers.get("X-Request-ID")
        if supplied_request_id and production:
            try:
                request.state.request_id = str(UUID(supplied_request_id))
            except ValueError:
                request.state.request_id = str(uuid4())
        else:
            request.state.request_id = supplied_request_id or str(uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/live")
    def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    def readiness(request: Request) -> dict[str, str]:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            raise HTTPException(503, "Database is unavailable") from None
        return {"status": "ready"}

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code = {401: "WEBHOOK_SIGNATURE_INVALID", 404: "NOT_FOUND", 409: "CONFLICT", 503: "SERVICE_UNAVAILABLE"}.get(exc.status_code, "REQUEST_FAILED")
        return _error(code, str(exc.detail), exc.status_code, request.state.request_id)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, __: RequestValidationError) -> JSONResponse:
        return _error("VALIDATION_ERROR", "Request validation failed", 422, request.state.request_id)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        if production:
            logging.getLogger("repoguard").error(
                "Unhandled application error request_id=%s exception_type=%s",
                request.state.request_id,
                type(exc).__name__,
            )
        else:
            logging.getLogger("repoguard").exception("Unhandled application error")
        return _error("INTERNAL_ERROR", "An internal error occurred", 500, request.state.request_id)
    return app


app = create_app()
