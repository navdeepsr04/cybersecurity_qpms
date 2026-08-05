from datetime import datetime
from sqlalchemy import (Column, Integer, String, Boolean, DateTime,
                         ForeignKey, BigInteger, Text)
from sqlalchemy.orm import relationship
from database import Base


class UserRole:
    ADMIN, FACULTY, STUDENT = "admin", "faculty", "student"
    ALL = {ADMIN, FACULTY, STUDENT}


class PaperStatus:
    PENDING, APPROVED, REJECTED = "pending", "approved", "rejected"
    ALL = {PENDING, APPROVED, REJECTED}


class AuditAction:
    REGISTER = "REGISTER"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    UPLOAD = "UPLOAD"
    DOWNLOAD = "DOWNLOAD"
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    DELETE = "DELETE"
    EDIT = "EDIT"
    ACCESS_DENIED = "ACCESS_DENIED"
    USER_UPDATE = "USER_UPDATE"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.STUDENT)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    papers = relationship("QuestionPaper", back_populates="uploader",
                           foreign_keys="QuestionPaper.uploaded_by")


class QuestionPaper(Base):
    __tablename__ = "question_papers"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    subject = Column(String(100), nullable=False)
    semester = Column(String(20), nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False, unique=True)
    file_path = Column(String(500), nullable=False)
    file_size = Column(BigInteger, default=0)
    file_hash = Column(String(64))
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    upload_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default=PaperStatus.PENDING, nullable=False)
    reviewed_by = Column(Integer, ForeignKey("users.id"))
    review_date = Column(DateTime)
    rejection_reason = Column(String(500))

    uploader = relationship("User", back_populates="papers", foreign_keys=[uploaded_by])


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    username = Column(String(50))
    action = Column(String(30), nullable=False)
    status = Column(String(10), default="SUCCESS", nullable=False)
    ip_address = Column(String(45))
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)