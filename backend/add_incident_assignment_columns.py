from sqlalchemy import text
from app.database import engine

columns = {
    "assigned_to": "VARCHAR(100)",
    "resolution_summary": "TEXT",
    "root_cause": "TEXT",
    "resolved_at": "TIMESTAMP WITH TIME ZONE",
    "closed_at": "TIMESTAMP WITH TIME ZONE",
}

with engine.begin() as connection:
    for column_name, column_type in columns.items():
        connection.execute(
            text(f"""
                ALTER TABLE incidents
                ADD COLUMN IF NOT EXISTS {column_name} {column_type}
            """)
        )

print("Incident assignment and resolution columns added or already exist.")