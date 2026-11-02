from app.database import SessionLocal
from app.models import AuditLog

db = SessionLocal()

try:
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(10)
        .all()
    )

    print(f"\nTotal records displayed: {len(logs)}")

    for log in logs:
        print({
            "id": log.id,
            "username": log.username,
            "action": log.action,
            "resource": log.resource_type,
            "ip_address": log.ip_address,
            "created_at": log.created_at,
        })

finally:
    db.close()