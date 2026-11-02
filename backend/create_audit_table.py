from app.database import Base, engine
from app import models

Base.metadata.create_all(
    bind=engine,
    tables=[models.AuditLog.__table__],
)

print("Audit logs table created or already exists.")