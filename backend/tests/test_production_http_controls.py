import asyncio
from dataclasses import replace
from uuid import UUID

import httpx
from fastapi import FastAPI, Request
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session

from app.api import auth
from app.core.http import RequestSizeLimitMiddleware
from app.core.rate_limit import AuthRateLimiter
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app import main


def test_auth_rate_limiter_enforces_window_and_recovers():
    limiter = AuthRateLimiter(limit=2, window_seconds=60)

    assert limiter.allow("127.0.0.1", now=100)
    assert limiter.allow("127.0.0.1", now=101)
    assert not limiter.allow("127.0.0.1", now=102)
    assert limiter.allow("127.0.0.1", now=160)


def test_login_endpoint_returns_429_after_configured_attempt_limit(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    app = create_app()

    def test_db():
        db = Session(engine)
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = test_db
    monkeypatch.setattr(auth, "_auth_rate_limiter", AuthRateLimiter(limit=1))
    monkeypatch.setattr(auth, "_auth_global_rate_limiter", AuthRateLimiter(limit=100))

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {"email": "rate-limit@example.test", "password": "synthetic-password-value"}
            first = await client.post(
                "/api/auth/login",
                json=payload,
                headers={"X-Forwarded-For": "198.51.100.10"},
            )
            second = await client.post(
                "/api/auth/login",
                json=payload,
                headers={"X-Forwarded-For": "203.0.113.250"},
            )
            assert first.status_code == 401
            assert second.status_code == 429

    try:
        asyncio.run(exercise())
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_global_auth_limit_applies_across_accounts(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    app = create_app()

    def test_db():
        db = Session(engine)
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = test_db
    monkeypatch.setattr(auth, "_auth_rate_limiter", AuthRateLimiter(limit=100))
    monkeypatch.setattr(auth, "_auth_global_rate_limiter", AuthRateLimiter(limit=1))

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post(
                "/api/auth/login",
                json={"email": "first@example.test", "password": "synthetic-password-value"},
            )
            second = await client.post(
                "/api/auth/login",
                json={"email": "second@example.test", "password": "synthetic-password-value"},
            )
            assert first.status_code == 401
            assert second.status_code == 429

    try:
        asyncio.run(exercise())
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_production_hsts_does_not_depend_on_forwarded_scheme_or_untrusted_request_id(monkeypatch):
    monkeypatch.setattr(main, "settings", replace(main.settings, environment="production"))
    app = create_app()

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/health/live",
                headers={"X-Request-ID": "synthetic-sensitive-request-id"},
            )
            assert response.status_code == 200
            assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
            assert str(UUID(response.headers["x-request-id"])) == response.headers["x-request-id"]
            assert "synthetic-sensitive-request-id" not in response.headers["x-request-id"]

    asyncio.run(exercise())


def test_request_size_limit_rejects_content_length_before_dispatch():
    app = FastAPI()
    app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=8)

    @app.post("/")
    async def accept_body(request: Request):
        return {"size": len(await request.body())}

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/", content=b"x" * 9)
            assert response.status_code == 413
            assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"

    asyncio.run(exercise())


def test_request_size_limit_rejects_chunked_body():
    app = FastAPI()
    app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=8)

    @app.post("/")
    async def accept_body(request: Request):
        return {"size": len(await request.body())}

    async def chunks():
        yield b"123456"
        yield b"789"

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/", content=chunks())
            assert response.status_code == 413
            assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"

    asyncio.run(exercise())
