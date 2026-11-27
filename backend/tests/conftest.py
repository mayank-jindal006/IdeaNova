"""Pytest runtime configuration for Windows ASGI tests.

Starlette's synchronous TestClient starts an AnyIO portal in a worker thread.
On this Windows runtime the Proactor policy blocks that portal before an ASGI
request is dispatched. The selector policy is the supported test-only loop
policy and does not affect the application process launched by Uvicorn.
"""
import asyncio
import os
import sys
from dataclasses import replace

import pytest

os.environ["REPOGUARD_JWT_SECRET"] = "repoguard-pytest-signing-key-only-not-for-any-environment-2026"

import app.core.scan_paths as scan_paths
from app.core.config import settings

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@pytest.fixture(autouse=True)
def configured_scan_root(request, monkeypatch):
    pytest_tmp_path = request.getfixturevalue("tmp_path")
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=pytest_tmp_path.parent))
