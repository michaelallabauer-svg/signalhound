from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.finding import Finding, FindingStatus
from app.models.service import Service


def test_change_detection_records_added_and_removed_inventory(client: TestClient, db_session: Session) -> None:
    baseline_at = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    comparison_at = baseline_at + timedelta(hours=1)

    organization_id = _create_organization(client)
    stable_asset_id = _create_asset(client, organization_id, "stable.example.com")
    removed_asset_id = _create_asset(client, organization_id, "removed.example.com")
    added_asset_id = _create_asset(client, organization_id, "added.example.com")
    removed_service_id = _create_service(client, stable_asset_id, 8443)
    added_service_id = _create_service(client, stable_asset_id, 9443)
    removed_finding_id = _create_finding(client, organization_id, stable_asset_id, "Old exposure")
    added_finding_id = _create_finding(client, organization_id, stable_asset_id, "New exposure")

    for asset_id in [stable_asset_id, removed_asset_id]:
        asset = db_session.get(Asset, asset_id)
        assert asset is not None
        asset.first_seen = baseline_at - timedelta(hours=1)
        asset.last_seen = baseline_at - timedelta(minutes=10)
        asset.updated_at = baseline_at - timedelta(minutes=10)

    added_asset = db_session.get(Asset, added_asset_id)
    assert added_asset is not None
    added_asset.first_seen = baseline_at + timedelta(minutes=10)
    added_asset.last_seen = baseline_at + timedelta(minutes=10)
    added_asset.updated_at = baseline_at + timedelta(minutes=10)

    removed_asset = db_session.get(Asset, removed_asset_id)
    assert removed_asset is not None
    removed_asset.active = False
    removed_asset.updated_at = baseline_at + timedelta(minutes=20)

    removed_service = db_session.get(Service, removed_service_id)
    assert removed_service is not None
    removed_service.first_seen = baseline_at - timedelta(hours=1)
    removed_service.last_seen = baseline_at - timedelta(minutes=10)
    removed_service.active = False
    removed_service.updated_at = baseline_at + timedelta(minutes=20)

    added_service = db_session.get(Service, added_service_id)
    assert added_service is not None
    added_service.first_seen = baseline_at + timedelta(minutes=15)
    added_service.last_seen = baseline_at + timedelta(minutes=15)
    added_service.updated_at = baseline_at + timedelta(minutes=15)

    removed_finding = db_session.get(Finding, removed_finding_id)
    assert removed_finding is not None
    removed_finding.first_seen = baseline_at - timedelta(hours=1)
    removed_finding.last_seen = baseline_at - timedelta(minutes=10)
    removed_finding.status = FindingStatus.RESOLVED
    removed_finding.updated_at = baseline_at + timedelta(minutes=20)

    added_finding = db_session.get(Finding, added_finding_id)
    assert added_finding is not None
    added_finding.first_seen = baseline_at + timedelta(minutes=25)
    added_finding.last_seen = baseline_at + timedelta(minutes=25)
    added_finding.updated_at = baseline_at + timedelta(minutes=25)
    db_session.commit()

    response = client.post(
        "/api/v1/change-sets/compare",
        json={
            "organization_id": organization_id,
            "baseline_at": baseline_at.isoformat(),
            "comparison_at": comparison_at.isoformat(),
        },
    )

    assert response.status_code == 201
    change_set = response.json()
    assert change_set["summary"]["total"] == 6
    assert change_set["summary"]["by_entity_type"] == {"ASSET": 2, "FINDING": 2, "SERVICE": 2}
    assert change_set["summary"]["by_change_type"] == {"ADDED": 3, "REMOVED": 3}

    event_keys = {(event["entity_type"], event["change_type"], event["entity_key"]) for event in change_set["events"]}
    assert ("ASSET", "ADDED", "ASSET:SUBDOMAIN:added.example.com") in event_keys
    assert ("ASSET", "REMOVED", "ASSET:SUBDOMAIN:removed.example.com") in event_keys
    assert ("SERVICE", "ADDED", f"SERVICE:{stable_asset_id}:TCP:9443") in event_keys
    assert ("SERVICE", "REMOVED", f"SERVICE:{stable_asset_id}:TCP:8443") in event_keys
    assert ("FINDING", "ADDED", f"FINDING:{stable_asset_id}:asset:manual:New exposure") in event_keys
    assert ("FINDING", "REMOVED", f"FINDING:{stable_asset_id}:asset:manual:Old exposure") in event_keys

    detail_response = client.get(f"/api/v1/change-sets/{change_set['id']}")
    assert detail_response.status_code == 200
    assert len(detail_response.json()["events"]) == 6

    audit_actions = list(db_session.scalars(select(AuditLog.action).order_by(AuditLog.id)))
    assert "change_set.created" in audit_actions


def test_change_detection_rejects_invalid_window(client: TestClient) -> None:
    organization_id = _create_organization(client)
    timestamp = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    response = client.post(
        "/api/v1/change-sets/compare",
        json={
            "organization_id": organization_id,
            "baseline_at": timestamp.isoformat(),
            "comparison_at": timestamp.isoformat(),
        },
    )

    assert response.status_code == 422


def _create_organization(client: TestClient) -> int:
    response = client.post("/api/v1/organizations", json={"name": "Change Corp"})
    assert response.status_code == 201
    return int(response.json()["id"])


def _create_asset(client: TestClient, organization_id: int, value: str) -> int:
    response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": organization_id,
            "asset_type": "SUBDOMAIN",
            "value": value,
            "source": "manual",
        },
    )
    assert response.status_code == 201
    return int(response.json()["id"])


def _create_service(client: TestClient, asset_id: int, port: int) -> int:
    response = client.post(
        "/api/v1/services",
        json={"asset_id": asset_id, "protocol": "TCP", "port": port, "source": "manual"},
    )
    assert response.status_code == 201
    return int(response.json()["id"])


def _create_finding(client: TestClient, organization_id: int, asset_id: int, title: str) -> int:
    response = client.post(
        "/api/v1/findings",
        json={
            "organization_id": organization_id,
            "asset_id": asset_id,
            "title": title,
            "severity": "MEDIUM",
            "source": "manual",
        },
    )
    assert response.status_code == 201
    return int(response.json()["id"])
