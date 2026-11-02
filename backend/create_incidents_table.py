
from app.database import Base, engine
from app.models import AnalysisHistory, Incident

Base.metadata.create_all(
    bind=engine,
    tables=[Incident.__table__],
)

print("Incident table created or already exists.")
print("Existing analysis_history table was not recreated.")
