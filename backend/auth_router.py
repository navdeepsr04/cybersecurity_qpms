from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

import config
from database import get_db
from models import User, AuditAction
from schemas import UserCreate, UserOut, Token
from security import hash_password, verify_password, create_access_token, get_current_user
from audit import log_action

router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory brute-force tracker: username -> list of recent failure timestamps.
# Fine for a single-process lab deployment; a real multi-worker production
# deployment would move this to Redis so all workers share state.
_LOGIN_FAILURES = defaultdict(list)


def _is_locked_out(username: str) -> bool:
    window = timedelta(minutes=config.LOGIN_LOCKOUT_MINUTES)
    now = datetime.utcnow()
    _LOGIN_FAILURES[username] = [t for t in _LOGIN_FAILURES[username] if now - t < window]
    return len(_LOGIN_FAILURES[username]) >= config.MAX_LOGIN_ATTEMPTS


def _record_failure(username: str):
    _LOGIN_FAILURES[username].append(datetime.utcnow())


def _clear_failures(username: str):
    _LOGIN_FAILURES.pop(username, None)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(400, "Email already registered")

    user = User(username=payload.username, email=payload.email,
                password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, AuditAction.REGISTER, user=user, ip=ip)
    return user


@router.post("/login", response_model=Token)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None

    if _is_locked_out(form.username):
        log_action(db, AuditAction.LOGIN_FAILED, status="FAILURE", username=form.username, ip=ip,
                   details="blocked: too many failed attempts")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                             "Too many failed login attempts. Try again later.")

    user = db.query(User).filter(User.username == form.username).first()

    if not user or not verify_password(form.password, user.password_hash):
        _record_failure(form.username)
        log_action(db, AuditAction.LOGIN_FAILED, status="FAILURE", username=form.username, ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password")

    if not user.is_active:
        log_action(db, AuditAction.LOGIN_FAILED, status="FAILURE", user=user, ip=ip, details="Account inactive")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is inactive")

    _clear_failures(form.username)
    token = create_access_token({"sub": user.username, "role": user.role})
    log_action(db, AuditAction.LOGIN_SUCCESS, user=user, ip=ip)
    return Token(access_token=token)


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    log_action(db, AuditAction.LOGOUT, user=user, ip=ip)
    return {"message": "Logged out"}