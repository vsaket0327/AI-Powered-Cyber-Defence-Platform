
import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import models  # Register all SQLAlchemy models


TEST_DATABASE_URL = (
    "postgresql+psycopg://cyber_app:"
    "local_dev_password_change_me@localhost:5432/cyber_defence_test"
)


@pytest.fixture(scope="session")
def test_engine():
    engine = create_engine(
        TEST_DATABASE_URL,
        pool_pre_ping=True,
    )

    # Safety check: never create or drop tables in the development database.
    if engine.url.database != "cyber_defence_test":
        raise RuntimeError("Refusing to run tests against a non-test database.")

    Base.metadata.create_all(bind=engine)

    yield engine

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(test_engine):
    connection = test_engine.connect()
    transaction = connection.begin()

    TestingSessionLocal = sessionmaker(
        bind=connection,
        autoflush=False,
        expire_on_commit=False,
    )

    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
