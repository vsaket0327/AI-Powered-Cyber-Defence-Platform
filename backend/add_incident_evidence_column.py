from sqlalchemy import text
from app.database import engine

with engine.begin() as conn:
    conn.execute(
        text("""
            ALTER TABLE incidents
            ADD COLUMN IF NOT EXISTS evidence JSON
            NOT NULL DEFAULT '{}'::json
        """)
    )

print("Incident evidence column added or already exists.")
