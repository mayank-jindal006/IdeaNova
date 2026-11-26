from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.auth import _bearer, current_user, decode_access_token, hash_password, issue_token, verify_password
from app.db.models import RevokedToken, User
from app.db.session import get_db
from app.schemas import AuthCredentials, TokenOut, UserOut
from app.settings import settings

router = APIRouter(prefix="/auth", tags=["auth"])


def _email(value: str) -> str:
    value = value.strip().lower()
    if value.count("@") != 1 or value.startswith("@") or value.endswith("@"):
        raise HTTPException(422, "A valid email address is required")
    return value


@router.post("/register", response_model=TokenOut)
def register(payload: AuthCredentials, db: Session = Depends(get_db)) -> TokenOut:
    email = _email(payload.email)
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "An account with that email already exists")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user); db.commit(); db.refresh(user)
    return TokenOut(access_token=issue_token(user), expires_in=settings.jwt_expiry_minutes * 60)


@router.post("/login", response_model=TokenOut)
def login(payload: AuthCredentials, db: Session = Depends(get_db)) -> TokenOut:
    user = db.scalar(select(User).where(User.email == _email(payload.email)))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    return TokenOut(access_token=issue_token(user), expires_in=settings.jwt_expiry_minutes * 60)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/logout", status_code=204)
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> None:
    if credentials is None:
        raise HTTPException(401, "Authentication is required")
    claims = decode_access_token(credentials.credentials)
    db.execute(delete(RevokedToken).where(RevokedToken.expires_at <= datetime.now(timezone.utc)))
    db.add(
        RevokedToken(
            token_id=claims["jti"],
            user_id=user.id,
            expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
        )
    )
    db.commit()
