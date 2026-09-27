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
) -> ScannerJob:
    job = ScannerJob(
        organization_id=organization_id,
        scope_id=scope_id,
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

