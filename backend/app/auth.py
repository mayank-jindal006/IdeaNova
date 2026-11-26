"""Authentication and tenant-ownership dependencies."""
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import os
import uuid
from typing import Any

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import RevokedToken, User
from app.db.session import get_db
from app.settings import settings

_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Use stdlib scrypt with per-password salt; never store plaintext."""
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$16384$8$1$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, n, r, p, salt, expected = encoded.split("$")
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(actual, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


def issue_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user.id),
            "iat": now,
            "exp": now + timedelta(minutes=settings.jwt_expiry_minutes),
            "jti": uuid.uuid4().hex,
        },
        settings.jwt_secret,
        algorithm="HS256",
    )


def decode_access_token(token: str) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=["HS256"],
        options={"require": ["exp", "iat", "sub", "jti"]},
    )
    if not isinstance(claims.get("jti"), str) or not claims["jti"]:
        raise jwt.InvalidTokenError("Token identifier is missing")
    return claims


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer), db: Session = Depends(get_db)) -> User:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "Authentication is required")
    try:
        claims = decode_access_token(credentials.credentials)
        subject = claims.get("sub")
        user = db.get(User, int(subject)) if subject else None
        revoked = db.scalar(select(RevokedToken.token_id).where(RevokedToken.token_id == claims["jti"]))
    except (jwt.PyJWTError, ValueError, TypeError):
        user = None
        revoked = True
    if not user or revoked:
        raise HTTPException(401, "Authentication is invalid or expired")
    return user


def owned_repo(db: Session, repo_id: int, user: User):
    from app.db.models import Repo
    repo = db.scalar(select(Repo).where(Repo.id == repo_id, Repo.owner_id == user.id))
    if not repo:
        raise HTTPException(404, "Repository not found")
    return repo
