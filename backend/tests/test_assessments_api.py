from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.assessment import AssessmentRun
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
