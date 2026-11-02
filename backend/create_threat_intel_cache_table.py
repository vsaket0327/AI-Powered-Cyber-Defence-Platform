from app.database import Base, engine
from app import models

Base.metadata.create_all(
    bind=engine,
    tables=[models.ThreatIntelCache.__table__],
)

print("Threat intelligence cache table created or already exists.")