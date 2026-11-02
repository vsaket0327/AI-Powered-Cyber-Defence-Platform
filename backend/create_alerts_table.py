from app.database import Base, engine
from app import models

Base.metadata.create_all(
    bind=engine,
    tables=[models.Alert.__table__],
)

print("Alerts table created or already exists.")