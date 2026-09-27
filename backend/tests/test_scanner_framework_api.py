from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.scanner_job import ScannerJob


def create_org_scope(client: TestClient) -> tuple[int, int]:
    org_response = client.post("/api/v1/organizations", json={"name": "Scanner Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])

    scope_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Scanner domain",
            "target_type": "DOMAIN",
            "target": "example.com",
        },
    )
    assert scope_response.status_code == 201
    return organization_id, int(scope_response.json()["id"])


def test_scanner_adapters_are_listed(client: TestClient) -> None:
    response = client.get("/api/v1/scanner-adapters")

    assert response.status_code == 200
    names = {adapter["name"] for adapter in response.json()}
    assert names == {"nmap", "amass", "nuclei"}
    assert all(adapter["execution_available"] is False for adapter in response.json())


def test_prepare_scanner_job_requires_scope_validation(client: TestClient, db_session: Session) -> None:
    organization_id, scope_id = create_org_scope(client)

    response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "adapter_name": "nmap",
            "target": "www.example.com",
        },
    )

    assert response.status_code == 201
    job = response.json()
    assert job["adapter_name"] == "nmap"
    assert job["target"] == "www.example.com"
    assert job["status"] == "PREPARED"
    assert job["prepared_config"]["execution"] == "not_implemented"

    stored_job = db_session.get(ScannerJob, job["id"])
    assert stored_job is not None
    assert stored_job.raw_output is None
    assert stored_job.normalized_result is None

    audit_actions = list(db_session.scalars(select(AuditLog.action).order_by(AuditLog.id)))
    assert "scope.validation.approved" in audit_actions
    assert "scanner.job.prepared" in audit_actions


def test_prepare_scanner_job_rejects_out_of_scope_target(client: TestClient, db_session: Session) -> None:
    organization_id, scope_id = create_org_scope(client)

    response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "adapter_name": "nmap",
            "target": "www.example.net",
        },
    )

    assert response.status_code == 403
    assert list(db_session.scalars(select(ScannerJob))) == []

    audit_actions = list(db_session.scalars(select(AuditLog.action).order_by(AuditLog.id)))
    assert "scope.validation.rejected" in audit_actions
    assert "scanner.job.rejected" in audit_actions


def test_prepare_scanner_job_rejects_unknown_adapter(client: TestClient) -> None:
    organization_id, scope_id = create_org_scope(client)

    response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "adapter_name": "unknown",
            "target": "www.example.com",
        },
    )

    assert response.status_code == 404

