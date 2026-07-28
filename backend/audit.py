from sqlalchemy.orm import Session
from models import AuditLog


def log_action(db: Session, action: str, status: str = "SUCCESS",
                user=None, username: str = None, ip: str = None, details: str = None):
    """Central audit writer -- every security-relevant event goes through here."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=username or (user.username if user else None),
        action=action,
        status=status,
        ip_address=ip,
        details=details,
    )
    db.add(entry)
    db.commit()