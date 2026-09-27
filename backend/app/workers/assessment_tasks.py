from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.assessment import AssessmentRunStatus
from app.repositories.assessments import get_assessment_run, set_assessment_run_status
from app.services.assessment_orchestration import execute_assessment_run
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.assessment_tasks.run_assessment")
def run_assessment_task(assessment_run_id: int) -> int:
    settings = get_settings()
    with SessionLocal() as db:
        run = get_assessment_run(db, assessment_run_id)
        if run is None:
            return assessment_run_id
        try:
            execute_assessment_run(db, run=run, timeout_seconds=settings.scanner_timeout_seconds)
        except Exception as exc:
            set_assessment_run_status(run, AssessmentRunStatus.FAILED, error_message=str(exc))
        db.commit()
    return assessment_run_id


def enqueue_assessment_run(assessment_run_id: int) -> None:
    run_assessment_task.delay(assessment_run_id)
