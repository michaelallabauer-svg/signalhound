from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment import AssessmentRun, AssessmentRunStatus


def create_assessment_run(
    db: Session,
    *,
    organization_id: int,
    scope_id: int,
    profile_name: str,
    target: str,
    summary: dict | None = None,
) -> AssessmentRun:
    run = AssessmentRun(
        organization_id=organization_id,
        scope_id=scope_id,
        profile_name=profile_name,
        target=target,
        status=AssessmentRunStatus.QUEUED,
        summary=summary or {},
    )
    db.add(run)
    db.flush()
    return run


def list_assessment_runs(db: Session, *, organization_id: int | None = None) -> list[AssessmentRun]:
    statement = select(AssessmentRun).order_by(AssessmentRun.id)
    if organization_id is not None:
        statement = statement.where(AssessmentRun.organization_id == organization_id)
    return list(db.scalars(statement))


def get_assessment_run(db: Session, assessment_run_id: int) -> AssessmentRun | None:
    return db.get(AssessmentRun, assessment_run_id)


def set_assessment_run_status(
    run: AssessmentRun,
    status: AssessmentRunStatus,
    *,
    summary: dict | None = None,
    error_message: str | None = None,
) -> AssessmentRun:
    run.status = status
    if summary is not None:
        run.summary = summary
    run.error_message = error_message
    return run
