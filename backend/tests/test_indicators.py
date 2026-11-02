
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.dependencies import get_current_user


# Controlled authenticated user for API tests
authenticated_user = MagicMock()
authenticated_user.id = 1
authenticated_user.username = "test_analyst"
authenticated_user.role = "analyst"
authenticated_user.is_active = True


def override_get_current_user():
    return authenticated_user


app.dependency_overrides[get_current_user] = override_get_current_user

client = TestClient(app)


def mock_db_session():
    """Create a mock session so tests do not write to PostgreSQL."""
    db = MagicMock()
    db.scalars.return_value.all.return_value = []
    return db


def test_analyze_domain_saves_analysis():
    db = mock_db_session()

    with (
        patch("app.main.SessionLocal", return_value=db),
        patch(
            "app.main.lookup_domain_reputation",
            new_callable=AsyncMock,
            return_value=None,
        ),
    ):
        response = client.post(
            "/api/v1/indicators/analyze",
            json={
                "indicator_type": "domain",
                "value": "example.com",
            },
        )

    assert response.status_code == 200

    body = response.json()
    assert body["indicator_type"] == "domain"
    assert body["indicator"] == "example.com"
    assert "risk_score" in body
    assert "evidence" in body

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()


def test_analyze_rejects_empty_value():
    response = client.post(
        "/api/v1/indicators/analyze",
        json={
            "indicator_type": "domain",
            "value": "",
        },
    )

    assert response.status_code == 422


def test_history_returns_empty_list():
    db = mock_db_session()

    with patch("app.main.SessionLocal", return_value=db):
        response = client.get("/api/v1/indicators/history")

    assert response.status_code == 200
    assert response.json() == {"count": 0, "items": []}


def test_history_rejects_invalid_limit():
    response = client.get(
        "/api/v1/indicators/history?limit=0"
    )

    assert response.status_code == 422
