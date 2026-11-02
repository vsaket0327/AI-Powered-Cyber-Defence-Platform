from sqlalchemy.orm import Session

from app.models import AuditLog, User


def log_audit_event(
    db: Session,
    action: str,
    user: User | None = None,
    username: str | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
):
    """
    Record a security-related event.
    Never include passwords, tokens, or API keys in details.
    """

    audit_record = AuditLog(
        user_id=user.id if user else None,
        username=username or (user.username if user else "Unknown"),
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        details=details or {},
        ip_address=ip_address,
    )

    db.add(audit_record)
    db.flush()

    return audit_record