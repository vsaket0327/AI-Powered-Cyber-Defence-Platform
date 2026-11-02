
from app.database import Base, engine
from app import models

Base.metadata.create_all(
    bind=engine,
    tables=[models.NetworkFlow.__table__],
)

print("Network flows table created or already exists.")
