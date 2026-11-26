from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.session import get_db


def db_session() -> Session:
    """Dependency marker kept in one place for contract route modules."""
    return Depends(get_db)
