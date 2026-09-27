import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings


def test_production_rejects_wildcard_cors() -> None:
    with pytest.raises(ValueError, match="Wildcard CORS"):
        Settings(environment="production", cors_origins="*")


def test_scanner_timeout_is_bounded() -> None:
    with pytest.raises(ValueError):
        Settings(scanner_timeout_seconds=1)


def test_request_body_size_limit_rejects_large_declared_body(client: TestClient) -> None:
    response = client.post(
        "/api/v1/organizations",
        content=b"x" * 1_048_577,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"
