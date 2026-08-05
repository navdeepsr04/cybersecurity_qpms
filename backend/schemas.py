from pydantic import BaseModel, EmailStr, field_validator
from models import UserRole
from datetime import datetime
from typing import Optional


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = UserRole.STUDENT

    @field_validator("username")
    @classmethod
    def username_len(cls, v):
        if not (3 <= len(v) <= 50):
            raise ValueError("username must be 3-50 characters")
        return v

    @field_validator("password")
    @classmethod
    def strong_password(cls, v):
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v

    @field_validator("role")
    @classmethod
    def valid_role(cls, v):
        if v not in (UserRole.FACULTY, UserRole.STUDENT):
            raise ValueError("role must be 'faculty' or 'student' (admin accounts are not self-registrable)")
        return v


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class PaperOut(BaseModel):
    id: int
    title: str
    subject: str
    semester: str
    original_filename: str
    upload_date: datetime
    status: str
    rejection_reason: Optional[str] = None

    class Config:
        from_attributes = True


class PaperUpdate(BaseModel):
    title: Optional[str] = None
    subject: Optional[str] = None
    semester: Optional[str] = None

class RejectPayload(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def reason_not_empty(cls, v):
        if not v.strip():
            raise ValueError("a rejection reason is required")
        return v


class AdminUserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

@field_validator("password")
@classmethod
def strong_password(cls, v):
    if len(v) < 8:
        raise ValueError("password must be at least 8 characters")
    if not any(c.isupper() for c in v):
        raise ValueError("password must contain at least one uppercase letter")
    if not any(c.islower() for c in v):
        raise ValueError("password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in v):
        raise ValueError("password must contain at least one digit")
    return v