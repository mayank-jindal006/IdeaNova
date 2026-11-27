from dataclasses import replace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.repos import create_repo
from app.core import scan_paths
from app.core.config import settings
from app.db.base import Base
from app.db.models import User
from app.schemas import RepoCreate


def test_local_registration_requires_opt_in_and_trusted_root(tmp_path, monkeypatch):
    root = tmp_path / 'trusted'
    root.mkdir()
    checkout = root / 'repo'
    checkout.mkdir()
    (checkout / '.git').mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / '.git').mkdir()
    monkeypatch.setattr(scan_paths, 'settings', replace(settings, scan_root=root))
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = User(email='local@example.invalid', password_hash='fixture')
        db.add(user)
        db.commit()
        monkeypatch.delenv('REPOGUARD_LOCAL_SCAN_ENABLED', raising=False)
        with pytest.raises(HTTPException) as disabled:
            create_repo(RepoCreate(local_path=str(checkout)), db, user)
        assert disabled.value.status_code == 403
        monkeypatch.setenv('REPOGUARD_LOCAL_SCAN_ENABLED', 'true')
        with pytest.raises(HTTPException) as escaped:
            create_repo(RepoCreate(local_path=str(outside)), db, user)
        assert escaped.value.status_code == 422
        with pytest.raises(HTTPException) as traversal:
            create_repo(RepoCreate(local_path=str(root / '..' / 'outside')), db, user)
        assert traversal.value.status_code == 422
        repo = create_repo(RepoCreate(local_path=str(checkout)), db, user)
        assert repo.full_name.startswith('local/')
        assert repo.source_type == 'local'
        assert checkout.is_dir() and (checkout / '.git').is_dir()
