from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.scanner_job import ScannerJob
from app.models.service import Service
from app.scanners.base import NormalizedScannerResult, PreparedScannerJob


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
    adapters = {adapter["name"]: adapter for adapter in response.json()}
    assert set(adapters) == {"nmap", "amass", "nuclei"}
    assert adapters["nmap"]["execution_available"] is True
    assert adapters["amass"]["execution_available"] is True
    assert adapters["nuclei"]["execution_available"] is True


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
    assert job["prepared_config"]["command"] == [
        "nmap",
        "-oX",
        "-",
        "-Pn",
        "-n",
        "--max-retries",
        "1",
        "--host-timeout",
        "240s",
        "-sV",
        "--version-intensity",
        "2",
        "-p",
        "80,443",
        "www.example.com",
    ]
    assert job["prepared_config"]["profile"] == "web_service_discovery"

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


def test_run_scanner_job_is_disabled_by_default(client: TestClient, monkeypatch) -> None:
    from app.api import scanner_jobs as scanner_jobs_api

    monkeypatch.setattr(
        scanner_jobs_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=False, scanner_timeout_seconds=30),
    )

    organization_id, scope_id = create_org_scope(client)
    create_response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "adapter_name": "nmap",
            "target": "www.example.com",
        },
    )
    assert create_response.status_code == 201

    run_response = client.post(f"/api/v1/scanner-jobs/{create_response.json()['id']}/run")

    assert run_response.status_code == 409
    assert "disabled" in run_response.json()["detail"]


def test_run_scanner_job_imports_normalized_results(
    client: TestClient,
    db_session: Session,
    monkeypatch,
) -> None:
    organization_id, scope_id = create_org_scope(client)
    create_response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "adapter_name": "nmap",
            "target": "www.example.com",
        },
    )
    assert create_response.status_code == 201
    job_id = create_response.json()["id"]

    class FakeAdapter:
        name = "nmap"
        execution_supported = True

        def execute(self, prepared_job: PreparedScannerJob) -> str:
            assert prepared_job.target == "www.example.com"
            return "raw-result"

        def parse_result(self, raw_output: str) -> dict:
            return {"raw": raw_output}

        def normalize_result(self, parsed_result: dict) -> NormalizedScannerResult:
            return NormalizedScannerResult(
                assets=[
                    {
                        "asset_type": "SUBDOMAIN",
                        "value": "www.example.com",
                        "source": "nmap",
                        "metadata": {"source": "fake"},
                    },
                    {
                        "asset_type": "HOST",
                        "value": "outside.example.net",
                        "source": "nmap",
                        "metadata": {"source": "fake"},
                    },
                ],
                services=[
                    {
                        "asset_type": "SUBDOMAIN",
                        "asset_value": "www.example.com",
                        "protocol": "TCP",
                        "port": 443,
                        "name": "https",
                        "source": "nmap",
                        "metadata": {"product": "fake"},
                    }
                ],
                findings=[
                    {
                        "asset_type": "SUBDOMAIN",
                        "asset_value": "www.example.com",
                        "title": "Exposed panel",
                        "description": "Panel is exposed",
                        "severity": "HIGH",
                        "source": "nuclei",
                        "external_reference": "exposed-panel",
                        "evidence": {"matched_at": "https://www.example.com/panel"},
                    }
                ],
                metadata={"parsed": parsed_result},
            )

    from app.api import scanner_jobs as scanner_jobs_api

    monkeypatch.setattr(
        scanner_jobs_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True, scanner_timeout_seconds=30),
    )
    monkeypatch.setattr(scanner_jobs_api.scanner_registry, "get", lambda name: FakeAdapter())

    run_response = client.post(f"/api/v1/scanner-jobs/{job_id}/run")

    assert run_response.status_code == 200
    job = run_response.json()
    assert job["status"] == "COMPLETED"
    assert job["raw_output"] == "raw-result"
    assert job["normalized_result"]["metadata"] == {"parsed": {"raw": "raw-result"}}

    assets = list(db_session.scalars(select(Asset).order_by(Asset.value)))
    assert [asset.value for asset in assets] == ["outside.example.net", "www.example.com"]
    in_scope_asset = next(asset for asset in assets if asset.value == "www.example.com")
    out_of_scope_asset = next(asset for asset in assets if asset.value == "outside.example.net")
    assert in_scope_asset.scope_id == scope_id
    assert in_scope_asset.known_asset is True
    assert out_of_scope_asset.scope_id is None
    assert out_of_scope_asset.known_asset is False

    services = list(db_session.scalars(select(Service)))
    assert len(services) == 1
    assert services[0].asset_id == in_scope_asset.id
    assert services[0].port == 443

    findings = list(db_session.scalars(select(Finding)))
    assert len(findings) == 1
    assert findings[0].asset_id == in_scope_asset.id
    assert findings[0].severity.value == "HIGH"
    assert findings[0].status.value == "NEW"

    audit_actions = list(db_session.scalars(select(AuditLog.action).order_by(AuditLog.id)))
    assert "scanner.started" in audit_actions
    assert "scanner.completed" in audit_actions
