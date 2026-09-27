from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scanner_job import ScannerJob, ScannerJobStatus


def create_scanner_job(
    db: Session,
    *,
    organization_id: int,
    scope_id: int,
    adapter_name: str,
    target: str,
    prepared_config: dict,
    assessment_run_id: int | None = None,
) -> ScannerJob:
    job = ScannerJob(
        organization_id=organization_id,
        scope_id=scope_id,
        assessment_run_id=assessment_run_id,
        adapter_name=adapter_name,
        target=target,
        status=ScannerJobStatus.PREPARED,
        prepared_config=prepared_config,
    )
    db.add(job)
    db.flush()
    return job


def list_scanner_jobs(
    db: Session,
    *,
    organization_id: int | None = None,
    adapter_name: str | None = None,
) -> list[ScannerJob]:
    statement = select(ScannerJob).order_by(ScannerJob.id)
    if organization_id is not None:
        statement = statement.where(ScannerJob.organization_id == organization_id)
    if adapter_name is not None:
        statement = statement.where(ScannerJob.adapter_name == adapter_name)
    return list(db.scalars(statement))


def get_scanner_job(db: Session, job_id: int) -> ScannerJob | None:
    return db.get(ScannerJob, job_id)


def set_scanner_job_status(
    job: ScannerJob,
    status: ScannerJobStatus,
    *,
    raw_output: str | None = None,
    normalized_result: dict | None = None,
    error_message: str | None = None,
) -> ScannerJob:
    job.status = status
    if raw_output is not None:
        job.raw_output = raw_output
    if normalized_result is not None:
        job.normalized_result = normalized_result
    job.error_message = error_message
    return job
