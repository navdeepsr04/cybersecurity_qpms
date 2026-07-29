import hashlib
import uuid
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

import config
from database import get_db
from models import QuestionPaper, PaperStatus, UserRole, AuditAction, User
from schemas import PaperOut, PaperUpdate
from security import require_role
from audit import log_action

router = APIRouter(prefix="/papers", tags=["papers"])


def _validate_pdf(file: UploadFile, content: bytes):
    ext = Path(file.filename).suffix.lower()
    if ext not in config.ALLOWED_EXTENSIONS:
        raise HTTPException(400, "Only .pdf files are allowed")
    if file.content_type not in config.ALLOWED_MIME_TYPES:
        raise HTTPException(400, "Invalid file type (MIME check failed)")
    if len(content) > config.MAX_FILE_SIZE_BYTES:
        mb = config.MAX_FILE_SIZE_BYTES // (1024 * 1024)
        raise HTTPException(400, f"File exceeds {mb} MB limit")
    if not content.startswith(b"%PDF-"):
        # Extension/MIME type are attacker-controlled; the real file's
        # magic bytes are the only thing we can trust.
        raise HTTPException(400, "File content is not a valid PDF")


# ---------------------------------------------------------------------------
# Faculty: upload / edit / delete / view own papers
# ---------------------------------------------------------------------------
@router.post("/upload", response_model=PaperOut, status_code=status.HTTP_201_CREATED)
def upload_paper(
    request: Request,
    title: str = Form(...),
    subject: str = Form(...),
    semester: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(UserRole.FACULTY)),
):
    ip = request.client.host if request.client else None
    content = file.file.read()
    _validate_pdf(file, content)

    # Never trust/reuse the client's filename on disk (path traversal,
    # collisions, unsafe characters) -- generate our own.
    stored_name = f"{uuid.uuid4().hex}.pdf"
    dest = config.UPLOAD_DIR / stored_name
    dest.write_bytes(content)

    paper = QuestionPaper(
        title=title, subject=subject, semester=semester,
        original_filename=file.filename, stored_filename=stored_name,
        file_path=str(dest), file_size=len(content),
        file_hash=hashlib.sha256(content).hexdigest(),
        uploaded_by=user.id, status=PaperStatus.PENDING,
    )
    db.add(paper)
    db.commit()
    db.refresh(paper)
    log_action(db, AuditAction.UPLOAD, user=user, ip=ip,
               details=f"paper_id={paper.id} file={file.filename}")
    return paper


@router.get("/mine", response_model=List[PaperOut])
def my_papers(db: Session = Depends(get_db), user: User = Depends(require_role(UserRole.FACULTY))):
    return (db.query(QuestionPaper)
            .filter(QuestionPaper.uploaded_by == user.id)
            .order_by(QuestionPaper.upload_date.desc()).all())


def _get_own_pending_paper(paper_id: int, db: Session, user: User) -> QuestionPaper:
    paper = db.query(QuestionPaper).filter(QuestionPaper.id == paper_id).first()
    if not paper:
        raise HTTPException(404, "Paper not found")
    if paper.uploaded_by != user.id:
        raise HTTPException(403, "You do not own this paper")
    if paper.status != PaperStatus.PENDING:
        raise HTTPException(400, "Only pending papers can be modified")
    return paper


@router.put("/{paper_id}", response_model=PaperOut)
def edit_paper(paper_id: int, payload: PaperUpdate, request: Request,
               db: Session = Depends(get_db), user: User = Depends(require_role(UserRole.FACULTY))):
    ip = request.client.host if request.client else None
    paper = _get_own_pending_paper(paper_id, db, user)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(paper, field, value)
    db.commit()
    db.refresh(paper)
    log_action(db, AuditAction.EDIT, user=user, ip=ip, details=f"paper_id={paper.id}")
    return paper


@router.delete("/{paper_id}")
def delete_paper(paper_id: int, request: Request,
                  db: Session = Depends(get_db), user: User = Depends(require_role(UserRole.FACULTY))):
    ip = request.client.host if request.client else None
    paper = _get_own_pending_paper(paper_id, db, user)
    Path(paper.file_path).unlink(missing_ok=True)
    db.delete(paper)
    db.commit()
    log_action(db, AuditAction.DELETE, user=user, ip=ip, details=f"paper_id={paper_id}")
    return {"message": "Paper deleted"}


# ---------------------------------------------------------------------------
# Student: search + download approved papers only
# ---------------------------------------------------------------------------
@router.get("/search", response_model=List[PaperOut])
def search_papers(subject: Optional[str] = None, semester: Optional[str] = None,
                   title: Optional[str] = None, db: Session = Depends(get_db),
                   user: User = Depends(require_role(UserRole.STUDENT))):
    q = db.query(QuestionPaper).filter(QuestionPaper.status == PaperStatus.APPROVED)
    if subject:
        q = q.filter(QuestionPaper.subject.ilike(f"%{subject}%"))
    if semester:
        q = q.filter(QuestionPaper.semester == semester)
    if title:
        q = q.filter(QuestionPaper.title.ilike(f"%{title}%"))
    return q.order_by(QuestionPaper.upload_date.desc()).all()


@router.get("/download/{paper_id}")
def download_paper(paper_id: int, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_role(UserRole.STUDENT))):
    ip = request.client.host if request.client else None
    paper = db.query(QuestionPaper).filter(QuestionPaper.id == paper_id).first()
    if not paper or paper.status != PaperStatus.APPROVED:
        log_action(db, AuditAction.DOWNLOAD, status="FAILURE", user=user, ip=ip,
                   details=f"paper_id={paper_id} not available")
        raise HTTPException(404, "Paper not found or not approved")

    file_path = Path(paper.file_path)
    # Defense in depth: the resolved path must actually live inside uploads/.
    if config.UPLOAD_DIR.resolve() not in file_path.resolve().parents or not file_path.exists():
        log_action(db, AuditAction.DOWNLOAD, status="FAILURE", user=user, ip=ip,
                   details=f"paper_id={paper_id} missing on disk")
        raise HTTPException(500, "File missing from storage")

    # Integrity check (the "I" in CIA): confirm the bytes on disk still
    # match what was uploaded, byte for byte.
    if hashlib.sha256(file_path.read_bytes()).hexdigest() != paper.file_hash:
        log_action(db, AuditAction.DOWNLOAD, status="FAILURE", user=user, ip=ip,
                   details=f"paper_id={paper_id} hash mismatch")
        raise HTTPException(500, "File integrity check failed")

    log_action(db, AuditAction.DOWNLOAD, user=user, ip=ip, details=f"paper_id={paper_id}")
    return FileResponse(path=file_path, filename=paper.original_filename, media_type="application/pdf")