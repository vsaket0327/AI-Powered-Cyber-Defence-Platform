from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "api"}

def test_root_identifies_service():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"
