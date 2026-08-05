from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from models import User, UserRole, QuestionPaper, PaperStatus, AuditLog, AuditAction
from schemas import PaperOut, UserOut, RejectPayload, AdminUserUpdate
from security import require_role
from audit import log_action

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Papers: view / approve / reject
# ---------------------------------------------------------------------------
@router.get("/papers")
def list_papers(status: str = PaperStatus.PENDING, db: Session = Depends(get_db),
                 admin: User = Depends(require_role(UserRole.ADMIN))):
    if status not in PaperStatus.ALL:
        raise HTTPException(400, f"status must be one of {sorted(PaperStatus.ALL)}")
    papers = (db.query(QuestionPaper).filter(QuestionPaper.status == status)
              .order_by(QuestionPaper.upload_date.desc()).all())
    return [
        {"id": p.id, "title": p.title, "subject": p.subject, "semester": p.semester,
         "original_filename": p.original_filename, "upload_date": p.upload_date,
         "status": p.status, "rejection_reason": p.rejection_reason,
         "uploaded_by": p.uploader.username if p.uploader else None}
        for p in papers
    ]


def _get_pending_paper(paper_id: int, db: Session) -> QuestionPaper:
    paper = db.query(QuestionPaper).filter(QuestionPaper.id == paper_id).first()
    if not paper:
        raise HTTPException(404, "Paper not found")
    if paper.status != PaperStatus.PENDING:
        raise HTTPException(400, "Only pending papers can be reviewed")
    return paper


@router.post("/papers/{paper_id}/approve", response_model=PaperOut)
def approve_paper(paper_id: int, request: Request, db: Session = Depends(get_db),
                   admin: User = Depends(require_role(UserRole.ADMIN))):
    ip = request.client.host if request.client else None
    paper = _get_pending_paper(paper_id, db)
    paper.status = PaperStatus.APPROVED
    paper.reviewed_by = admin.id
    paper.review_date = datetime.utcnow()
    db.commit()
    db.refresh(paper)
    log_action(db, AuditAction.APPROVE, user=admin, ip=ip, details=f"paper_id={paper.id}")
    return paper


@router.post("/papers/{paper_id}/reject", response_model=PaperOut)
def reject_paper(paper_id: int, payload: RejectPayload, request: Request,
                  db: Session = Depends(get_db), admin: User = Depends(require_role(UserRole.ADMIN))):
    ip = request.client.host if request.client else None
    paper = _get_pending_paper(paper_id, db)
    paper.status = PaperStatus.REJECTED
    paper.reviewed_by = admin.id
    paper.review_date = datetime.utcnow()
    paper.rejection_reason = payload.reason
    db.commit()
    db.refresh(paper)
    log_action(db, AuditAction.REJECT, user=admin, ip=ip,
               details=f"paper_id={paper.id} reason={payload.reason}")
    return paper


# ---------------------------------------------------------------------------
# Users: list + manage (role / active status)
# ---------------------------------------------------------------------------
@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_role(UserRole.ADMIN))):
    return db.query(User).order_by(User.id).all()


@router.patch("/users/{user_id}", response_model=UserOut)
def manage_user(user_id: int, payload: AdminUserUpdate, request: Request,
                 db: Session = Depends(get_db), admin: User = Depends(require_role(UserRole.ADMIN))):
    ip = request.client.host if request.client else None
    if user_id == admin.id:
        # Prevents an admin from locking themselves out or fat-fingering
        # their own role away -- self-modification isn't allowed here.
        raise HTTPException(400, "Cannot modify your own account through this endpoint")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")

    changes = payload.model_dump(exclude_unset=True)
    if "role" in changes and changes["role"] not in UserRole.ALL:
        raise HTTPException(400, f"role must be one of {sorted(UserRole.ALL)}")

    for field, value in changes.items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    log_action(db, AuditAction.USER_UPDATE, user=admin, ip=ip,
               details=f"target_user={target.username} changes={changes}")
    return target


# ---------------------------------------------------------------------------
# Audit logs
# ---------------------------------------------------------------------------
@router.get("/logs")
def view_logs(limit: int = 100, username: Optional[str] = None, action: Optional[str] = None,
              db: Session = Depends(get_db), admin: User = Depends(require_role(UserRole.ADMIN))):
    q = db.query(AuditLog)
    if username:
        q = q.filter(AuditLog.username == username)
    if action:
        q = q.filter(AuditLog.action == action)
    logs = q.order_by(AuditLog.timestamp.desc()).limit(min(limit, 500)).all()
    return [
        {"id": l.id, "username": l.username, "action": l.action, "status": l.status,
         "ip_address": l.ip_address, "details": l.details, "timestamp": l.timestamp}
        for l in logs
    ]