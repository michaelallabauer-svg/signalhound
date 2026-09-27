from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def create_organization(client: TestClient) -> int:
    response = client.post("/api/v1/organizations", json={"name": "Example Corp"})

    assert response.status_code == 201
    return int(response.json()["id"])


def test_scope_crud_and_validation_flow(client: TestClient, db_session: Session) -> None:
    organization_id = create_organization(client)

    create_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Example external domain",
            "target_type": "DOMAIN",
            "target": "Example.COM.",
        },
    )

    assert create_response.status_code == 201
    scope = create_response.json()
    assert scope["target"] == "example.com"
    assert scope["scan_zone"] == "EXTERNAL"
    assert scope["active"] is True

    allowed_response = client.post(
        "/api/v1/scopes/validate",
        json={"organization_id": organization_id, "target": "www.example.com"},
    )

    assert allowed_response.status_code == 200
    assert allowed_response.json()["allowed"] is True
    assert allowed_response.json()["scope_id"] == scope["id"]

    denied_response = client.post(
        "/api/v1/scopes/validate",
        json={"organization_id": organization_id, "target": "example.net"},
    )

    assert denied_response.status_code == 200
    assert denied_response.json()["allowed"] is False
    assert denied_response.json()["scope_id"] is None

    delete_response = client.delete(f"/api/v1/scopes/{scope['id']}")
    assert delete_response.status_code == 204

    inactive_response = client.post(
        "/api/v1/scopes/validate",
        json={"organization_id": organization_id, "target": "www.example.com"},
    )

    assert inactive_response.status_code == 200
    assert inactive_response.json()["allowed"] is False

    audit_actions = list(db_session.scalars(select(AuditLog.action).order_by(AuditLog.id)))
    assert "scope.created" in audit_actions
    assert "scope.validation.approved" in audit_actions
    assert "scope.validation.rejected" in audit_actions
    assert "scope.deleted" in audit_actions


def test_cidr_scope_allows_contained_ip_only(client: TestClient) -> None:
    organization_id = create_organization(client)

    create_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Public range",
            "target_type": "CIDR",
            "target": "203.0.113.0/24",
        },
    )
    assert create_response.status_code == 201

    allowed_response = client.post(
        "/api/v1/scopes/validate",
        json={"organization_id": organization_id, "target": "203.0.113.42"},
    )
    denied_response = client.post(
        "/api/v1/scopes/validate",
        json={"organization_id": organization_id, "target": "198.51.100.42"},
    )

    assert allowed_response.json()["allowed"] is True
    assert denied_response.json()["allowed"] is False


def test_internal_it_cidr_scope_allows_network_target(client: TestClient) -> None:
    organization_id = create_organization(client)

    create_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Internal subnet",
            "target_type": "CIDR",
            "target": "192.168.10.0/24",
            "scan_zone": "INTERNAL_IT",
        },
    )
    assert create_response.status_code == 201
    assert create_response.json()["scan_zone"] == "INTERNAL_IT"

    network_response = client.post(
        "/api/v1/scopes/validate",
        json={
            "organization_id": organization_id,
            "target": "192.168.10.0/24",
            "scan_zone": "INTERNAL_IT",
        },
    )
    host_response = client.post(
        "/api/v1/scopes/validate",
        json={
            "organization_id": organization_id,
            "target": "192.168.10.42",
            "scan_zone": "INTERNAL_IT",
        },
    )
    external_zone_response = client.post(
        "/api/v1/scopes/validate",
        json={
            "organization_id": organization_id,
            "target": "192.168.10.42",
            "scan_zone": "EXTERNAL",
        },
    )

    assert network_response.json()["allowed"] is True
    assert host_response.json()["allowed"] is True
    assert external_zone_response.json()["allowed"] is False


def test_cidr_scope_normalizes_host_address_network_target(client: TestClient) -> None:
    organization_id = create_organization(client)

    create_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Home LAN",
            "target_type": "CIDR",
            "target": "192.168.0.1/24",
            "scan_zone": "INTERNAL_IT",
        },
    )
    assert create_response.status_code == 201
    assert create_response.json()["target"] == "192.168.0.0/24"

    validation_response = client.post(
        "/api/v1/scopes/validate",
        json={
            "organization_id": organization_id,
            "target": "192.168.0.1/24",
            "scan_zone": "INTERNAL_IT",
        },
    )

    assert validation_response.status_code == 200
    assert validation_response.json()["allowed"] is True
    assert validation_response.json()["normalized_target"] == "192.168.0.0/24"


def test_hostname_scope_does_not_authorize_parent_or_sibling(client: TestClient) -> None:
    organization_id = create_organization(client)

    create_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Single host",
            "target_type": "HOSTNAME",
            "target": "app.example.com",
        },
    )
    assert create_response.status_code == 201

    exact_response = client.post(
        "/api/v1/scopes/validate",
        json={"organization_id": organization_id, "target": "app.example.com"},
    )
    sibling_response = client.post(
        "/api/v1/scopes/validate",
        json={"organization_id": organization_id, "target": "api.example.com"},
    )

    assert exact_response.json()["allowed"] is True
    assert sibling_response.json()["allowed"] is False


def test_scope_requires_existing_organization(client: TestClient) -> None:
    response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": 999,
            "name": "Missing org scope",
            "target_type": "DOMAIN",
            "target": "example.com",
        },
    )

    assert response.status_code == 404


def test_invalid_cidr_scope_returns_validation_error(client: TestClient) -> None:
    organization_id = create_organization(client)

    response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Invalid range",
            "target_type": "CIDR",
            "target": "not-a-network",
        },
    )

    assert response.status_code == 422
