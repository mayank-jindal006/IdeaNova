from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import current_user, hash_password, issue_token, verify_password
from app.db.models import User
from app.db.session import get_db
from app.schemas import AuthCredentials, TokenOut, UserOut
from app.settings import settings
from app.services.audit import record_audit_event

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
    db.add(user)
    try:
        db.flush()
        record_audit_event(db, user, "account.registered")
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An account with that email already exists") from None
    db.refresh(user)
    return TokenOut(access_token=issue_token(user), expires_in=settings.jwt_expiry_minutes * 60)


@router.post("/login", response_model=TokenOut)
def login(payload: AuthCredentials, db: Session = Depends(get_db)) -> TokenOut:
    user = db.scalar(select(User).where(User.email == _email(payload.email)))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    record_audit_event(db, user, "account.login")
    db.commit()
    return TokenOut(access_token=issue_token(user), expires_in=settings.jwt_expiry_minutes * 60)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user
