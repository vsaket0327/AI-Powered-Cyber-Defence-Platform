from app.database import Base, engine
from app import models

Base.metadata.create_all(
    bind=engine,
    tables=[models.AIAnalysisReport.__table__],
)

print("AI analysis reports table created or already exists.")