import pytest
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset import AssetType
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.scanner_job import ScannerJob
from app.models.service import Service
from app.scanners.base import NormalizedScannerResult, PreparedScannerJob
from app.repositories.assets import observe_asset


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
    assert set(adapters) == {"nmap", "amass", "nuclei", "web_fingerprint"}
    assert adapters["nmap"]["execution_available"] is True
    assert adapters["amass"]["execution_available"] is True
    assert adapters["nuclei"]["execution_available"] is True
    assert adapters["web_fingerprint"]["execution_available"] is True


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


def test_prepare_internal_it_scanner_job_uses_internal_scope_zone(client: TestClient) -> None:
    org_response = client.post("/api/v1/organizations", json={"name": "Internal Scanner Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])
    scope_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Internal host",
            "target_type": "IP",
            "target": "192.168.30.10",
            "scan_zone": "INTERNAL_IT",
        },
    )
    assert scope_response.status_code == 201

    response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_response.json()["id"],
            "adapter_name": "nmap",
            "target": "192.168.30.10",
        },
    )

    assert response.status_code == 201
    job = response.json()
    assert job["target"] == "192.168.30.10"
    assert job["prepared_config"]["command"][-1] == "192.168.30.10"


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


def test_run_scanner_job_rejects_tampered_stored_command(
    client: TestClient,
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

    class TamperAwareAdapter:
        name = "nmap"
        execution_supported = True

        def prepare_job(self, target) -> PreparedScannerJob:
            return PreparedScannerJob(
                adapter_name=self.name,
                target=target.value,
                config={"command": ["nmap", "--safe", target.value]},
                command=["nmap", "--safe", target.value],
            )

        def execute(self, prepared_job: PreparedScannerJob) -> str:
            raise AssertionError("tampered job must fail before execution")

    from app.api import scanner_jobs as scanner_jobs_api

    monkeypatch.setattr(
        scanner_jobs_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True, scanner_timeout_seconds=30),
    )
    monkeypatch.setattr(scanner_jobs_api.scanner_registry, "get", lambda name: TamperAwareAdapter())

    run_response = client.post(f"/api/v1/scanner-jobs/{job_id}/run")

    assert run_response.status_code == 409
    assert "Stored scanner command" in run_response.json()["detail"]


def test_run_internal_it_scanner_job_imports_internal_asset_as_known(
    client: TestClient,
    db_session: Session,
    monkeypatch,
) -> None:
    org_response = client.post("/api/v1/organizations", json={"name": "Internal Import Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])
    scope_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Internal host",
            "target_type": "IP",
            "target": "192.168.40.10",
            "scan_zone": "INTERNAL_IT",
        },
    )
    assert scope_response.status_code == 201
    scope_id = int(scope_response.json()["id"])
    create_response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "adapter_name": "nmap",
            "target": "192.168.40.10",
        },
    )
    assert create_response.status_code == 201
    job_id = create_response.json()["id"]

    class FakeAdapter:
        name = "nmap"
        execution_supported = True

        def execute(self, prepared_job: PreparedScannerJob) -> str:
            return "raw-result"

        def parse_result(self, raw_output: str) -> dict:
            return {"raw": raw_output}

        def normalize_result(self, parsed_result: dict) -> NormalizedScannerResult:
            return NormalizedScannerResult(
                assets=[
                    {
                        "asset_type": "IP",
                        "value": "192.168.40.10",
                        "source": "nmap",
                        "metadata": {"source": "fake"},
                    }
                ]
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
    asset = db_session.scalar(select(Asset).where(Asset.value == "192.168.40.10"))
    assert asset is not None
    assert asset.scope_id == scope_id
    assert asset.known_asset is True

    audit_actions = list(db_session.scalars(select(AuditLog.action).order_by(AuditLog.id)))
    assert "scanner.started" in audit_actions
    assert "scanner.completed" in audit_actions


def test_nmap_cidr_run_deactivates_scope_assets_not_seen_again(
    client: TestClient,
    db_session: Session,
    monkeypatch,
) -> None:
    org_response = client.post("/api/v1/organizations", json={"name": "Internal Reconcile Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])
    scope_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Internal subnet",
            "target_type": "CIDR",
            "target": "192.168.50.0/24",
            "scan_zone": "INTERNAL_IT",
        },
    )
    assert scope_response.status_code == 201
    scope_id = int(scope_response.json()["id"])
    stale_asset, _ = observe_asset(
        db_session,
        organization_id=organization_id,
        asset_type=AssetType.IP,
        value="192.168.50.99",
        source="nmap",
        scope_id=scope_id,
        known_asset=True,
        metadata={"source": "previous scan"},
    )
    db_session.commit()

    create_response = client.post(
        "/api/v1/scanner-jobs",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "adapter_name": "nmap",
            "target": "192.168.50.0/24",
        },
    )
    assert create_response.status_code == 201
    job_id = create_response.json()["id"]

    class FakeAdapter:
        name = "nmap"
        execution_supported = True

        def execute(self, prepared_job: PreparedScannerJob) -> str:
            return "raw-result"

        def parse_result(self, raw_output: str) -> dict:
            return {"raw": raw_output}

        def normalize_result(self, parsed_result: dict) -> NormalizedScannerResult:
            return NormalizedScannerResult(
                assets=[
                    {
                        "asset_type": "IP",
                        "value": "192.168.50.10",
                        "source": "nmap",
                        "metadata": {"source": "current scan"},
                    }
                ]
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
    db_session.refresh(stale_asset)
    current_asset = db_session.scalar(select(Asset).where(Asset.value == "192.168.50.10"))
    assert stale_asset.active is False
    assert current_asset is not None
    assert current_asset.active is True


@pytest.mark.parametrize("adapter_name", ["nuclei", "web_fingerprint"])
def test_web_adapters_cidr_rejected_without_creating_job(client: TestClient, db_session: Session, adapter_name: str) -> None:
    org = client.post("/api/v1/organizations", json={"name": "CIDR regression"}).json()
    scope = client.post("/api/v1/scopes", json={
        "organization_id": org["id"], "name": "LAN", "target_type": "CIDR",
        "target": "192.168.0.0/24", "scan_zone": "INTERNAL_IT",
    })
    assert scope.status_code == 201
    response = client.post("/api/v1/scanner-jobs", json={
        "organization_id": org["id"], "scope_id": scope.json()["id"],
        "adapter_name": adapter_name, "target": "192.168.0.0/24",
    })
    assert response.status_code == 422
    assert "Nmap" in response.json()["detail"]
    assert list(db_session.scalars(select(ScannerJob))) == []


def test_fingerprint_failures_do_not_import_inventory(client: TestClient, db_session: Session, monkeypatch) -> None:
    from app.scanners.placeholders import WebFingerprintAdapter
    from app.services.scanner_execution import run_scanner_job
    organization_id, scope_id = create_org_scope(client)
    response = client.post("/api/v1/scanner-jobs", json={
        "organization_id": organization_id, "scope_id": scope_id,
        "adapter_name": "web_fingerprint", "target": "example.com",
    })
    assert response.status_code == 201
    adapter = WebFingerprintAdapter()
    monkeypatch.setattr(adapter, "execute", lambda prepared: '{"target":"example.com","results":[{"port":443,"scheme":"https","error":"DNS failed"}]}')
    job = db_session.get(ScannerJob, response.json()["id"])
    run_scanner_job(db_session, job=job, adapter=adapter, timeout_seconds=5)
    assert list(db_session.scalars(select(Asset))) == []
    assert list(db_session.scalars(select(Service))) == []
    assert job.normalized_result["metadata"]["endpoint_attempts"][0]["error"] == "DNS failed"


def test_fingerprint_repair_preserves_discovery_and_history(client: TestClient, db_session: Session) -> None:
    from app.repositories.services import observe_service
    from app.models.service import ServiceProtocol, ServiceObservation
    from app.services.fingerprint_repair import retire_unconfirmed_fingerprints
    organization_id, scope_id = create_org_scope(client)
    artifact, _ = observe_asset(db_session, organization_id=organization_id, asset_type=AssetType.HOST,
        value="192.168.0.0/24", source="web_fingerprint", scope_id=scope_id, known_asset=True, metadata={})
    host, _ = observe_asset(db_session, organization_id=organization_id, asset_type=AssetType.HOST,
        value="example.com", source="nmap", scope_id=scope_id, known_asset=True, metadata={})
    bad, _ = observe_service(db_session, asset_id=artifact.id, protocol=ServiceProtocol.TCP, port=443,
        name="https", source="web_fingerprint", metadata={"error":"DNS failed"})
    good, _ = observe_service(db_session, asset_id=host.id, protocol=ServiceProtocol.TCP, port=443,
        name="https", source="nmap", metadata={})
    observe_service(db_session, asset_id=host.id, protocol=ServiceProtocol.TCP, port=443,
        name="https", source="web_fingerprint", metadata={"error":"Connection refused"})
    result = retire_unconfirmed_fingerprints(db_session)
    assert result == {"services": [bad.id], "assets": [artifact.id]}
    assert good.active and host.active
    assert not bad.active and not artifact.active
    assert len(list(db_session.scalars(select(ServiceObservation)))) == 3
    assert retire_unconfirmed_fingerprints(db_session) == {"services": [], "assets": []}
