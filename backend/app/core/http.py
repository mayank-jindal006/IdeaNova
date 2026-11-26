from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("repoguard.http")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Adds a request ID and emits metadata only—never request bodies or secrets."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Unhandled request error request_id=%s path=%s", request_id, request.url.path)
            raise
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request_id=%s method=%s path=%s status=%s duration_ms=%.1f",
            request_id, request.method, request.url.path, response.status_code, (time.perf_counter() - started) * 1000,
        )
        return response


def error_response(status_code: int, message: str, request: Request, details: object | None = None) -> JSONResponse:
    payload: dict[str, object] = {"error": {"message": message, "request_id": getattr(request.state, "request_id", None)}}
    if details is not None:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Pydantic errors contain field names/types, not raw request data.
        return error_response(422, "Request validation failed", request, exc.errors())

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        logger.exception("Unhandled application exception request_id=%s", getattr(request.state, "request_id", None))
        return error_response(500, "An unexpected internal error occurred.", request)
