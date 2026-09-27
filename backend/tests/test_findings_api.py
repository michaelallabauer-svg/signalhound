from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.finding import FindingObservation


def create_asset(client: TestClient) -> tuple[int, int]:
    org_response = client.post("/api/v1/organizations", json={"name": "Finding Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])

    asset_response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": organization_id,
            "asset_type": "HOST",
            "value": "app.example.com",
            "source": "manual",
        },
    )
    assert asset_response.status_code == 201
    return organization_id, int(asset_response.json()["id"])


def test_finding_observations_preserve_history(client: TestClient, db_session: Session) -> None:
    organization_id, asset_id = create_asset(client)
    payload = {
        "organization_id": organization_id,
        "asset_id": asset_id,
        "title": "Missing security header",
        "description": "Header is absent",
        "severity": "LOW",
        "source": "manual",
        "external_reference": "manual-001",
        "evidence": {"header": "x-frame-options"},
    }

    first_response = client.post("/api/v1/findings", json=payload)
    second_response = client.post(
        "/api/v1/findings",
        json={**payload, "evidence": {"header": "x-content-type-options"}},
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201
    first = first_response.json()
    second = second_response.json()
    assert second["id"] == first["id"]
    assert second["first_seen"] == first["first_seen"]
    assert second["status"] == "NEW"
    assert second["evidence"] == {"header": "x-content-type-options"}

    history_response = client.get(f"/api/v1/findings/{first['id']}/observations")
    assert history_response.status_code == 200
    observations = history_response.json()
    assert len(observations) == 2
    assert observations[0]["evidence"] == {"header": "x-frame-options"}
    assert observations[1]["evidence"] == {"header": "x-content-type-options"}

    observation_count = db_session.scalar(select(func.count(FindingObservation.id)))
    assert observation_count == 2


def test_finding_status_change_is_audited(client: TestClient, db_session: Session) -> None:
    organization_id, asset_id = create_asset(client)
    create_response = client.post(
        "/api/v1/findings",
        json={
            "organization_id": organization_id,
            "asset_id": asset_id,
            "title": "TLS issue",
            "severity": "MEDIUM",
            "source": "manual",
        },
    )
    assert create_response.status_code == 201

    update_response = client.patch(
        f"/api/v1/findings/{create_response.json()['id']}/status",
        json={"status": "ACKNOWLEDGED", "remediation": "Track with owner"},
    )

    assert update_response.status_code == 200
    finding = update_response.json()
    assert finding["status"] == "ACKNOWLEDGED"
    assert finding["remediation"] == "Track with owner"

    audit_actions = list(db_session.scalars(select(AuditLog.action).order_by(AuditLog.id)))
    assert "finding.status.changed" in audit_actions

