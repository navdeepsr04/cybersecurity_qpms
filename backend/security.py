from datetime import datetime, timedelta

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from fastapi import Depends, HTTPException, Request, status   # Request added
from models import User, AuditAction                          # AuditAction added
from audit import log_action 

import config
from database import get_db
from models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# bcrypt truncates input at 72 bytes silently otherwise; capped explicitly
# so long passwords fail predictably instead of surprising anyone.
_MAX_PW_BYTES = 72


def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:_MAX_PW_BYTES]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    pw_bytes = plain.encode("utf-8")[:_MAX_PW_BYTES]
    return bcrypt.checkpw(pw_bytes, hashed.encode("utf-8"))


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    cred_error = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise cred_error
    except JWTError:
        raise cred_error

    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise cred_error
    return user


def require_role(*allowed_roles: str):
    """Dependency factory: require_role(UserRole.ADMIN) protects an endpoint.
    Every rejection is itself an audited event -- unauthorized access
    attempts are exactly what Accounting is supposed to catch."""
    def checker(request: Request, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> User:
        if user.role not in allowed_roles:
            ip = request.client.host if request.client else None
            log_action(db, AuditAction.ACCESS_DENIED, status="FAILURE", user=user, ip=ip,
                       details=f"needed one of {allowed_roles}, path={request.url.path}")
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Not enough permissions")
        return user
    return checker