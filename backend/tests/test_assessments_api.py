from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.assessment import AssessmentRun
from app.models.assessment import AssessmentRunStatus
from app.models.scanner_job import ScannerJob


def create_org_scope(client: TestClient) -> tuple[int, int]:
    org_response = client.post("/api/v1/organizations", json={"name": "Assessment Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])

    scope_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Assessment domain",
            "target_type": "DOMAIN",
            "target": "example.com",
        },
    )
    assert scope_response.status_code == 201
    return organization_id, int(scope_response.json()["id"])


def test_scan_profiles_are_listed(client: TestClient) -> None:
    response = client.get("/api/v1/scan-profiles")

    assert response.status_code == 200
    profiles = {profile["name"]: profile for profile in response.json()}
    assert profiles["external_quick"]["adapter_sequence"] == ["nmap", "nuclei"]
    assert profiles["external_discovery"]["adapter_sequence"] == ["amass", "nmap", "nuclei"]
    assert profiles["internal_it_quick"]["scan_zone"] == "INTERNAL_IT"
    assert profiles["internal_it_quick"]["adapter_sequence"] == ["nmap"]


def test_create_assessment_prepares_jobs_and_enqueues(
    client: TestClient,
    db_session: Session,
    monkeypatch,
) -> None:
    from app.api import assessments as assessments_api

    enqueued: list[int] = []
    monkeypatch.setattr(
        assessments_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True),
    )
    monkeypatch.setattr(assessments_api, "enqueue_assessment_run", lambda run_id: enqueued.append(run_id))

    organization_id, scope_id = create_org_scope(client)

    response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "profile_name": "external_quick",
            "target": "www.example.com",
        },
    )

    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "QUEUED"
    assert run["profile_name"] == "external_quick"
    assert run["target"] == "www.example.com"
    assert run["summary"]["adapters"] == ["nmap", "nuclei"]
    assert enqueued == [run["id"]]

    stored_run = db_session.get(AssessmentRun, run["id"])
    assert stored_run is not None
    jobs = db_session.query(ScannerJob).order_by(ScannerJob.id).all()
    assert [job.adapter_name for job in jobs] == ["nmap", "nuclei"]
    assert all(job.assessment_run_id == stored_run.id for job in jobs)

    detail_response = client.get(f"/api/v1/assessments/{run['id']}/detail")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["id"] == run["id"]
    assert [job["adapter_name"] for job in detail["jobs"]] == ["nmap", "nuclei"]


def test_create_assessment_rejects_out_of_scope_target(
    client: TestClient,
    monkeypatch,
) -> None:
    from app.api import assessments as assessments_api

    monkeypatch.setattr(
        assessments_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True),
    )
    organization_id, scope_id = create_org_scope(client)

    response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "profile_name": "external_quick",
            "target": "www.example.net",
        },
    )

    assert response.status_code == 403


def test_create_internal_it_assessment_prepares_nmap_job(
    client: TestClient,
    db_session: Session,
    monkeypatch,
) -> None:
    from app.api import assessments as assessments_api

    enqueued: list[int] = []
    monkeypatch.setattr(
        assessments_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True),
    )
    monkeypatch.setattr(assessments_api, "enqueue_assessment_run", lambda run_id: enqueued.append(run_id))

    org_response = client.post("/api/v1/organizations", json={"name": "Internal Assessment Corp"})
    assert org_response.status_code == 201
    organization_id = int(org_response.json()["id"])
    scope_response = client.post(
        "/api/v1/scopes",
        json={
            "organization_id": organization_id,
            "name": "Internal subnet",
            "target_type": "CIDR",
            "target": "192.168.20.0/24",
            "scan_zone": "INTERNAL_IT",
        },
    )
    assert scope_response.status_code == 201
    scope_id = int(scope_response.json()["id"])

    response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "profile_name": "internal_it_quick",
            "target": "192.168.20.0/24",
        },
    )

    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "QUEUED"
    assert run["summary"]["adapters"] == ["nmap"]
    assert enqueued == [run["id"]]

    jobs = db_session.query(ScannerJob).order_by(ScannerJob.id).all()
    assert [job.adapter_name for job in jobs] == ["nmap"]
    assert jobs[0].target == "192.168.20.0/24"


def test_create_assessment_rejects_profile_scope_zone_mismatch(
    client: TestClient,
    monkeypatch,
) -> None:
    from app.api import assessments as assessments_api

    monkeypatch.setattr(
        assessments_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True),
    )
    organization_id, scope_id = create_org_scope(client)

    response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "profile_name": "internal_it_quick",
            "target": "www.example.com",
        },
    )

    assert response.status_code == 422
    assert "zone" in response.json()["detail"]


def test_archive_completed_assessment_hides_it_from_default_list(
    client: TestClient,
    db_session: Session,
    monkeypatch,
) -> None:
    from app.api import assessments as assessments_api

    monkeypatch.setattr(
        assessments_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True),
    )
    monkeypatch.setattr(assessments_api, "enqueue_assessment_run", lambda run_id: None)
    organization_id, scope_id = create_org_scope(client)

    create_response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "profile_name": "external_quick",
            "target": "www.example.com",
        },
    )
    assert create_response.status_code == 201
    run_id = create_response.json()["id"]
    stored_run = db_session.get(AssessmentRun, run_id)
    assert stored_run is not None
    stored_run.status = AssessmentRunStatus.COMPLETED
    db_session.commit()

    archive_response = client.post(f"/api/v1/assessments/{run_id}/archive")

    assert archive_response.status_code == 200
    assert archive_response.json()["status"] == "ARCHIVED"
    default_list = client.get(f"/api/v1/assessments?organization_id={organization_id}")
    archived_list = client.get(f"/api/v1/assessments?organization_id={organization_id}&include_archived=true")
    assert default_list.json() == []
    assert [run["id"] for run in archived_list.json()] == [run_id]


def test_archive_rejects_active_assessment(
    client: TestClient,
    monkeypatch,
) -> None:
    from app.api import assessments as assessments_api

    monkeypatch.setattr(
        assessments_api,
        "get_settings",
        lambda: SimpleNamespace(scanner_execution_enabled=True),
    )
    monkeypatch.setattr(assessments_api, "enqueue_assessment_run", lambda run_id: None)
    organization_id, scope_id = create_org_scope(client)
    create_response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": organization_id,
            "scope_id": scope_id,
            "profile_name": "external_quick",
            "target": "www.example.com",
        },
    )
    assert create_response.status_code == 201

    archive_response = client.post(f"/api/v1/assessments/{create_response.json()['id']}/archive")

    assert archive_response.status_code == 409
