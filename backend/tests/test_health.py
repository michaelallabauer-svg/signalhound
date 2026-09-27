from fastapi.testclient import TestClient

from app.main import app


def test_application_starts() -> None:
    assert app.title == "SignalHound"


def test_health_response() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

