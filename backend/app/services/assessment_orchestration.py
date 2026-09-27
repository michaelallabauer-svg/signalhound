from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import AssessmentRun, AssessmentRunStatus
from app.models.scanner_job import ScannerJob, ScannerJobStatus
from app.models.scope import ScanZone
from app.repositories.assessments import set_assessment_run_status
from app.repositories.scanner_jobs import create_scanner_job, list_scanner_jobs
from app.repositories.scopes import get_scope
from app.scanners.base import ScannerTarget
from app.scanners.registry import scanner_registry
from app.services.audit import record_audit_event
from app.services.scan_profiles import ScanProfile
from app.services.scanner_execution import run_scanner_job
from app.services.scope_validation import ScopeValidator


def prepare_assessment_jobs(db: Session, *, run: AssessmentRun, profile: ScanProfile) -> list[ScannerJob]:
    jobs: list[ScannerJob] = []
    scanner_target = ScannerTarget(
        value=run.target,
        scope_id=run.scope_id,
        organization_id=run.organization_id,
    )

    for adapter_name in profile.adapter_sequence:
        adapter = scanner_registry.get(adapter_name)
        if adapter is None:
            raise ValueError(f"Scanner adapter not found: {adapter_name}")
        prepared = adapter.prepare_job(scanner_target)
        job = create_scanner_job(
            db,
            organization_id=run.organization_id,
            scope_id=run.scope_id,
            adapter_name=prepared.adapter_name,
            target=prepared.target,
            prepared_config=prepared.config,
            assessment_run_id=run.id,
        )
        jobs.append(job)
        record_audit_event(
            db,
            action="assessment.job.prepared",
            affected_object_type="scanner_job",
            affected_object_id=str(job.id),
            result="success",
            metadata={
                "assessment_run_id": run.id,
                "profile_name": run.profile_name,
                "adapter_name": job.adapter_name,
                "target": job.target,
            },
        )

    run.summary = {
        "profile": profile.name,
        "job_ids": [job.id for job in jobs],
        "adapters": list(profile.adapter_sequence),
        "assets": 0,
        "services": 0,
        "findings": 0,
    }
    return jobs


def execute_assessment_run(db: Session, *, run: AssessmentRun, timeout_seconds: int) -> AssessmentRun:
    if run.status not in {AssessmentRunStatus.QUEUED, AssessmentRunStatus.FAILED}:
        raise ValueError("Only QUEUED or FAILED assessment runs can be executed")

    run.started_at = datetime.now(UTC)
    set_assessment_run_status(run, AssessmentRunStatus.RUNNING)
    record_audit_event(
        db,
        action="assessment.started",
        affected_object_type="assessment_run",
        affected_object_id=str(run.id),
        result="started",
        metadata={"profile_name": run.profile_name, "target": run.target},
    )
    db.flush()

    jobs = list(
        db.scalars(
            select(ScannerJob)
            .where(ScannerJob.assessment_run_id == run.id)
            .order_by(ScannerJob.id)
        )
    )
    failed_jobs: list[int] = []

    for job in jobs:
        adapter = scanner_registry.get(job.adapter_name)
        if adapter is None:
            failed_jobs.append(job.id)
            job.status = ScannerJobStatus.FAILED
            job.error_message = f"Scanner adapter not found: {job.adapter_name}"
            continue
        run_scanner_job(db, job=job, adapter=adapter, timeout_seconds=timeout_seconds)
        if job.status == ScannerJobStatus.FAILED:
            failed_jobs.append(job.id)
        db.flush()

    summary = summarize_assessment_jobs(jobs, profile_name=run.profile_name)
    summary["failed_job_ids"] = failed_jobs
    run.completed_at = datetime.now(UTC)
    status = AssessmentRunStatus.FAILED if failed_jobs else AssessmentRunStatus.COMPLETED
    set_assessment_run_status(
        run,
        status,
        summary=summary,
        error_message=f"{len(failed_jobs)} scanner job(s) failed" if failed_jobs else None,
    )
    record_audit_event(
        db,
        action="assessment.completed" if not failed_jobs else "assessment.failed",
        affected_object_type="assessment_run",
        affected_object_id=str(run.id),
        result="success" if not failed_jobs else "failed",
        metadata={"profile_name": run.profile_name, "target": run.target, "summary": summary},
    )
    db.flush()
    return run


def summarize_assessment_jobs(jobs: list[ScannerJob], *, profile_name: str) -> dict[str, Any]:
    totals = {"assets": 0, "services": 0, "findings": 0}
    job_summaries = []
    for job in jobs:
        result = job.normalized_result or {}
        counts = {
            "assets": _count_result_items(result, "assets"),
            "services": _count_result_items(result, "services"),
            "findings": _count_result_items(result, "findings"),
        }
        for key, value in counts.items():
            totals[key] += value
        job_summaries.append(
            {
                "id": job.id,
                "adapter_name": job.adapter_name,
                "target": job.target,
                "status": job.status.value,
                **counts,
            }
        )
    return {
        "profile": profile_name,
        "job_ids": [job.id for job in jobs],
        "jobs": job_summaries,
        **totals,
    }


def _count_result_items(result: dict[str, Any], key: str) -> int:
    value = result.get(key)
    return len(value) if isinstance(value, list) else 0


WEB_SERVICE_PORTS = {80, 443, 8080, 8443}


def prepare_vulnerability_followups(db: Session, *, run: AssessmentRun) -> dict[str, Any]:
    if run.status != AssessmentRunStatus.COMPLETED:
        raise ValueError("Vulnerability checks can only be prepared for completed assessments")

    nuclei = scanner_registry.get("nuclei")
    if nuclei is None:
        raise ValueError("Scanner adapter not found: nuclei")

    targets = _web_targets_from_assessment_jobs(db, run=run)
    existing_targets = {
        job.target
        for job in list_scanner_jobs(db, organization_id=run.organization_id, adapter_name="nuclei")
        if job.assessment_run_id == run.id
    }
    prepared_jobs: list[ScannerJob] = []
    skipped_targets: list[str] = []

    for target in targets:
        if target in existing_targets:
            skipped_targets.append(target)
            continue

        scanner_target = ScannerTarget(value=target, scope_id=run.scope_id, organization_id=run.organization_id)
        prepared = nuclei.prepare_job(scanner_target)
        job = create_scanner_job(
            db,
            organization_id=run.organization_id,
            scope_id=run.scope_id,
            adapter_name=prepared.adapter_name,
            target=prepared.target,
            prepared_config=prepared.config,
            assessment_run_id=run.id,
        )
        prepared_jobs.append(job)
        record_audit_event(
            db,
            action="assessment.followup.prepared",
            affected_object_type="scanner_job",
            affected_object_id=str(job.id),
            result="success",
            metadata={
                "assessment_run_id": run.id,
                "adapter_name": job.adapter_name,
                "target": job.target,
            },
        )

    return {
        "assessment_run_id": run.id,
        "adapter_name": "nuclei",
        "candidate_targets": targets,
        "prepared_job_ids": [job.id for job in prepared_jobs],
        "prepared_targets": [job.target for job in prepared_jobs],
        "skipped_targets": skipped_targets,
    }


def _web_targets_from_assessment_jobs(db: Session, *, run: AssessmentRun) -> list[str]:
    scan_zone = _scan_zone_for_run(db, run)
    targets: set[str] = set()
    jobs = list(
        db.scalars(
            select(ScannerJob)
            .where(ScannerJob.assessment_run_id == run.id)
            .order_by(ScannerJob.id)
        )
    )
    for job in jobs:
        result = job.normalized_result or {}
        services = result.get("services", [])
        if not isinstance(services, list):
            continue
        for service in services:
            if not isinstance(service, dict) or not _is_web_service(service):
                continue
            target = str(service.get("asset_value", "")).strip().lower().rstrip(".")
            if not target:
                continue
            validation = ScopeValidator().validate(
                db,
                organization_id=run.organization_id,
                target=target,
                scan_zone=scan_zone,
            )
            if validation.allowed and validation.scope_id == run.scope_id:
                targets.add(validation.normalized_target)
    return sorted(targets)


def _is_web_service(service: dict[str, Any]) -> bool:
    try:
        port = int(service.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    name = str(service.get("name") or "").lower()
    return port in WEB_SERVICE_PORTS or "http" in name


def _scan_zone_for_run(db: Session, run: AssessmentRun) -> ScanZone:
    scope = get_scope(db, run.scope_id)
    return scope.scan_zone if scope is not None else ScanZone.EXTERNAL
