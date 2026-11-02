
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.dependencies import get_db
from app.models import User
from app.security import hash_password, SECRET_KEY, ALGORITHM


@pytest.fixture
def auth_client(db_session):
    original_overrides = app.dependency_overrides.copy()

    def override_get_db():
        yield db_session

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()
    app.dependency_overrides.update(original_overrides)


@pytest.fixture
def test_user(db_session):
    user = User(
        username="auth_test_user",
        email="auth_test@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role="analyst",
        is_active=True,
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return user


def test_missing_token_returns_401(auth_client):
    response = auth_client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_invalid_token_returns_401(auth_client):
    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.token.value"},
    )

    assert response.status_code == 401


def test_expired_token_returns_401(auth_client, test_user):
    expired_payload = {
        "sub": str(test_user.id),
        "role": test_user.role,
        "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
    }

    token = jwt.encode(
        expired_payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_valid_token_returns_user(auth_client, test_user):
    from app.security import create_access_token

    token = create_access_token(
        user_id=test_user.id,
        role=test_user.role,
    )

    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["username"] == test_user.username
    assert response.json()["role"] == "analyst"


def test_inactive_user_returns_401(auth_client, test_user, db_session):
    test_user.is_active = False
    db_session.commit()

    from app.security import create_access_token

    token = create_access_token(
        user_id=test_user.id,
        role=test_user.role,
    )

    response = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401

def test_analyst_cannot_access_admin_users(auth_client, test_user):
    from app.security import create_access_token

    token = create_access_token(
        user_id=test_user.id,
        role="analyst",
    )

    response = auth_client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_admin_can_access_admin_users(auth_client, db_session):
    from app.security import create_access_token

    admin_user = User(
        username="auth_test_admin",
        email="auth_admin@example.com",
        hashed_password=hash_password("AdminPassword123!"),
        role="admin",
        is_active=True,
    )

    db_session.add(admin_user)
    db_session.commit()
    db_session.refresh(admin_user)

    token = create_access_token(
        user_id=admin_user.id,
        role="admin",
    )

    response = auth_client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["count"] >= 1
