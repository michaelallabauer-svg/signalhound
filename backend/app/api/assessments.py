from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.scanner_job import ScannerJob
from app.models.scope import ScanZone
from app.repositories.assessments import create_assessment_run, get_assessment_run, list_assessment_runs
from app.repositories.organizations import get_organization
from app.repositories.scopes import get_scope
from app.schemas.assessment import AssessmentRunCreate, AssessmentRunDetailRead, AssessmentRunRead, ScanProfileRead
from app.schemas.scanner import ScannerJobRead
from app.services.assessment_orchestration import prepare_assessment_jobs
from app.services.audit import record_audit_event
from app.services.scan_profiles import get_scan_profile, list_scan_profiles
from app.services.scope_validation import ScopeValidator
from app.workers.assessment_tasks import enqueue_assessment_run

router = APIRouter(tags=["assessments"])


@router.get("/scan-profiles", response_model=list[ScanProfileRead])
def profiles() -> list[ScanProfileRead]:
    return [ScanProfileRead(**profile.__dict__) for profile in list_scan_profiles()]


@router.post("/assessments", response_model=AssessmentRunRead, status_code=status.HTTP_201_CREATED)
def create(payload: AssessmentRunCreate, db: Session = Depends(get_db)) -> AssessmentRunRead:
    settings = get_settings()
    if not settings.scanner_execution_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scanner execution is disabled. Set SCANNER_EXECUTION_ENABLED=true to run assessments.",
        )

    if get_organization(db, payload.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    scope = get_scope(db, payload.scope_id)
    if scope is None or scope.organization_id != payload.organization_id or not scope.active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active scope not found")

    profile = get_scan_profile(payload.profile_name)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan profile not found")
    if profile.scan_zone != ScanZone.EXTERNAL.value:
        raise HTTPException(status_code=422, detail="Only EXTERNAL scan profiles are implemented")

    validation = ScopeValidator().validate(
        db,
        organization_id=payload.organization_id,
        target=payload.target,
        scan_zone=ScanZone.EXTERNAL,
    )
    if not validation.allowed or validation.scope_id != payload.scope_id:
        record_audit_event(
            db,
            action="assessment.rejected",
            affected_object_type="assessment_run",
            affected_object_id=None,
            result="rejected",
            metadata={
                "profile_name": payload.profile_name,
                "target": validation.normalized_target,
                "organization_id": payload.organization_id,
                "scope_id": payload.scope_id,
                "reason": "target failed scope validation",
            },
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Assessment target is outside the provided scope")

    run = create_assessment_run(
        db,
        organization_id=payload.organization_id,
        scope_id=payload.scope_id,
        profile_name=profile.name,
        target=validation.normalized_target,
    )
    try:
        prepare_assessment_jobs(db, run=run, profile=profile)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    record_audit_event(
        db,
        action="assessment.queued",
        affected_object_type="assessment_run",
        affected_object_id=str(run.id),
        result="queued",
        metadata={
            "profile_name": run.profile_name,
            "target": run.target,
            "organization_id": run.organization_id,
            "scope_id": run.scope_id,
            "job_ids": run.summary.get("job_ids", []),
        },
    )
    db.commit()
    enqueue_assessment_run(run.id)
    db.refresh(run)
    return run


@router.get("/assessments", response_model=list[AssessmentRunRead])
def list_all(organization_id: int | None = None, db: Session = Depends(get_db)) -> list[AssessmentRunRead]:
    return list_assessment_runs(db, organization_id=organization_id)


@router.get("/assessments/{assessment_run_id}", response_model=AssessmentRunRead)
def get(assessment_run_id: int, db: Session = Depends(get_db)) -> AssessmentRunRead:
    run = get_assessment_run(db, assessment_run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment run not found")
    return run


@router.get("/assessments/{assessment_run_id}/detail", response_model=AssessmentRunDetailRead)
def get_detail(assessment_run_id: int, db: Session = Depends(get_db)) -> AssessmentRunDetailRead:
    run = get_assessment_run(db, assessment_run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment run not found")

    jobs = list(
        db.scalars(
            select(ScannerJob)
            .where(ScannerJob.assessment_run_id == assessment_run_id)
            .order_by(ScannerJob.id)
        )
    )
    run_payload = AssessmentRunRead.model_validate(run, from_attributes=True).model_dump()
    return AssessmentRunDetailRead(
        **run_payload,
        jobs=[ScannerJobRead.model_validate(job, from_attributes=True) for job in jobs],
    )
