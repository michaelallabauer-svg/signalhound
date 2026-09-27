from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import AssetObservation
from app.models.service import ServiceObservation


def create_org_and_scope(client: TestClient) -> tuple[int, int]:
    org_response = client.post("/api/v1/organizations", json={"name": "Inventory Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])

    scope_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Inventory external domain",
            "target_type": "DOMAIN",
            "target": "example.com",
        },
    )
    assert scope_response.status_code == 201
    return organization_id, int(scope_response.json()["id"])


def test_asset_observations_preserve_history(client: TestClient, db_session: Session) -> None:
    organization_id, scope_id = create_org_and_scope(client)

    first_response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "asset_type": "SUBDOMAIN",
            "value": "WWW.Example.COM.",
            "source": "manual",
            "known_asset": True,
            "metadata": {"note": "first sighting"},
        },
    )
    second_response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "asset_type": "SUBDOMAIN",
            "value": "www.example.com",
            "source": "manual",
            "metadata": {"note": "second sighting"},
        },
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201
    first_asset = first_response.json()
    second_asset = second_response.json()
    assert second_asset["id"] == first_asset["id"]
    assert second_asset["value"] == "www.example.com"
    assert second_asset["known_asset"] is True
    assert second_asset["first_seen"] == first_asset["first_seen"]

    observations_response = client.get(f"/api/v1/assets/{first_asset['id']}/observations")
    assert observations_response.status_code == 200
    observations = observations_response.json()
    assert len(observations) == 2
    assert observations[0]["metadata"] == {"note": "first sighting"}
    assert observations[1]["metadata"] == {"note": "second sighting"}

    observation_count = db_session.scalar(select(func.count(AssetObservation.id)))
    assert observation_count == 2


def test_asset_with_scope_must_be_authorized(client: TestClient) -> None:
    organization_id, scope_id = create_org_and_scope(client)

    response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "asset_type": "SUBDOMAIN",
            "value": "www.example.net",
            "source": "manual",
        },
    )

    assert response.status_code == 403


def test_unverified_asset_can_be_recorded_without_scope(client: TestClient) -> None:
    organization_id, _ = create_org_and_scope(client)

    response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": organization_id,
            "asset_type": "HOST",
            "value": "unverified.example.net",
            "source": "manual",
        },
    )

    assert response.status_code == 201
    asset = response.json()
    assert asset["scope_id"] is None
    assert asset["known_asset"] is False


def test_service_observations_preserve_history(client: TestClient, db_session: Session) -> None:
    organization_id, scope_id = create_org_and_scope(client)
    asset_response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "asset_type": "SUBDOMAIN",
            "value": "app.example.com",
            "source": "manual",
        },
    )
    assert asset_response.status_code == 201
    asset_id = int(asset_response.json()["id"])

    first_response = client.post(
        "/api/v1/services",
        json={
            "asset_id": asset_id,
            "protocol": "TCP",
            "port": 443,
            "name": "https",
            "source": "manual",
            "metadata": {"banner": "first"},
        },
    )
    second_response = client.post(
        "/api/v1/services",
        json={
            "asset_id": asset_id,
            "protocol": "TCP",
            "port": 443,
            "name": "https",
            "source": "manual",
            "metadata": {"banner": "second"},
        },
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201
    first_service = first_response.json()
    second_service = second_response.json()
    assert second_service["id"] == first_service["id"]
    assert second_service["first_seen"] == first_service["first_seen"]

    observations_response = client.get(f"/api/v1/services/{first_service['id']}/observations")
    assert observations_response.status_code == 200
    observations = observations_response.json()
    assert len(observations) == 2
    assert observations[0]["metadata"] == {"banner": "first"}
    assert observations[1]["metadata"] == {"banner": "second"}

    observation_count = db_session.scalar(select(func.count(ServiceObservation.id)))
    assert observation_count == 2


def test_service_requires_existing_asset(client: TestClient) -> None:
    response = client.post(
        "/api/v1/services",
        json={
            "asset_id": 999,
            "protocol": "TCP",
            "port": 443,
            "source": "manual",
        },
    )

    assert response.status_code == 404
