"""Real HTTP ASGITransport tests; avoids the Windows TestClient portal issue."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import Finding, FindingStatus, FindingType, Repo, Scan, ScanStatus, ScanTrigger
from app.db.session import get_db
from app.main import create_app
from app.settings import settings


def test_authentication_and_two_user_tenant_isolation():
    # Sync FastAPI dependencies execute in worker threads. StaticPool keeps the
    # isolated in-memory database shared across those ASGI request threads.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    app = create_app()

    def test_db():
        db = Session(engine)
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = test_db

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            unauthenticated = await client.get("/api/repos")
            assert unauthenticated.status_code == 401
            a = await client.post("/api/auth/register", json={"email": "a@example.test", "password": "correct horse battery staple"})
            assert a.status_code == 200
            assert (await client.post("/api/auth/register", json={"email": "a@example.test", "password": "correct horse battery staple"})).status_code == 409
            assert (await client.post("/api/auth/login", json={"email": "a@example.test", "password": "wrong password value"})).status_code == 401
            a_headers = {"Authorization": f"Bearer {a.json()['access_token']}"}
            assert (await client.get("/api/auth/me", headers=a_headers)).json()["email"] == "a@example.test"
            created = await client.post("/api/repos", headers=a_headers, json={"full_name": "a/repo", "default_branch": "main"})
            assert created.status_code == 200
            repo_id = created.json()["id"]
            db = Session(engine)
            scan = Scan(repo_id=repo_id, trigger=ScanTrigger.manual, status=ScanStatus.done)
            db.add(scan); db.flush()
            finding = Finding(scan_id=scan.id, repo_id=repo_id, fingerprint="a", type=FindingType.secret, rule_id="rule", title="masked", severity=None, scanner="gitleaks", aliases=[], references=[], in_history_only=False, confidence=.9, status=FindingStatus.open, owasp_ids=[], asvs_ids=[])
            db.add(finding); db.commit(); finding_id, scan_id = finding.id, scan.id; db.close()
            assert (await client.get(f"/api/repos/{repo_id}", headers=a_headers)).status_code == 200
            assert (await client.get(f"/api/scans/{scan_id}", headers=a_headers)).status_code == 200
            assert (await client.get(f"/api/findings/{finding_id}", headers=a_headers)).status_code == 200
            b = await client.post("/api/auth/register", json={"email": "b@example.test", "password": "correct horse battery staple 2"})
            b_headers = {"Authorization": f"Bearer {b.json()['access_token']}"}
            for path in (f"/api/repos/{repo_id}", f"/api/scans/{scan_id}", f"/api/findings/{finding_id}", f"/api/repos/{repo_id}/findings", f"/api/repos/{repo_id}/scan"):
                response = await (client.post(path, headers=b_headers) if path.endswith('/scan') else client.get(path, headers=b_headers))
                assert response.status_code == 404
            assert (await client.get("/api/dashboard/summary", headers=b_headers)).json()["totals"]["repos"] == 0
            second_repo = await client.post(
                "/api/repos",
                headers=b_headers,
                json={"full_name": "a/repo", "default_branch": "main"},
            )
            assert second_repo.status_code == 200
            assert second_repo.json()["id"] != repo_id
            expired = jwt.encode({"sub": "1", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)}, settings.jwt_secret, algorithm="HS256")
            assert (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})).status_code == 401
            assert (await client.get("/api/auth/me", headers={"Authorization": "Bearer invalid"})).status_code == 401
            assert (await client.post("/api/repositories/scan", headers=b_headers, json={"repo_id": repo_id})).status_code == 404
            db = Session(engine); db.add(Repo(full_name="legacy/repo", default_branch="main", owner_id=None)); db.commit(); db.close()
            assert all(item["full_name"] != "legacy/repo" for item in (await client.get("/api/repos", headers=a_headers)).json())
            assert (await client.post("/api/auth/logout", headers=b_headers)).status_code == 204
            assert (await client.get("/api/auth/me", headers=b_headers)).status_code == 401
    asyncio.run(exercise())
    app.dependency_overrides.clear()
