from app.database import Base, engine
from app import models

Base.metadata.create_all(
    bind=engine,
    tables=[models.NetworkAnomaly.__table__],
)

print("Network anomalies table created or already exists.")