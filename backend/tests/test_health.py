from app.main import app


def test_application_starts() -> None:
    assert app.title == "SignalHound"


def test_health_response(client) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
