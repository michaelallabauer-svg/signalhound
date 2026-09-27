from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scope import ScanZone
from app.repositories.organizations import get_organization
from app.repositories.scanner_jobs import create_scanner_job, get_scanner_job, list_scanner_jobs
from app.repositories.scopes import get_scope
from app.schemas.scanner import ScannerJobCreate, ScannerJobRead
from app.scanners.base import ScannerTarget
from app.scanners.registry import scanner_registry
from app.services.audit import record_audit_event
from app.services.scope_validation import ScopeValidator

router = APIRouter(prefix="/scanner-jobs", tags=["scanner-jobs"])


@router.post("", response_model=ScannerJobRead, status_code=status.HTTP_201_CREATED)
def prepare(payload: ScannerJobCreate, db: Session = Depends(get_db)) -> ScannerJobRead:
    if get_organization(db, payload.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    scope = get_scope(db, payload.scope_id)
    if scope is None or scope.organization_id != payload.organization_id or not scope.active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active scope not found")

    adapter = scanner_registry.get(payload.adapter_name)
    if adapter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scanner adapter not found")

    validation = ScopeValidator().validate(
        db,
        organization_id=payload.organization_id,
        target=payload.target,
        scan_zone=ScanZone.EXTERNAL,
    )
    if not validation.allowed or validation.scope_id != payload.scope_id:
        record_audit_event(
            db,
            action="scanner.job.rejected",
            affected_object_type="scanner_job",
            affected_object_id=None,
            result="rejected",
            metadata={
                "adapter_name": payload.adapter_name,
                "target": validation.normalized_target,
                "organization_id": payload.organization_id,
                "scope_id": payload.scope_id,
                "reason": "target failed scope validation",
            },
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Scanner target is outside the provided scope")

    scanner_target = ScannerTarget(
        value=validation.normalized_target,
        scope_id=payload.scope_id,
        organization_id=payload.organization_id,
    )
    try:
        prepared = adapter.prepare_job(scanner_target)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    job = create_scanner_job(
        db,
        organization_id=payload.organization_id,
        scope_id=payload.scope_id,
        adapter_name=prepared.adapter_name,
        target=prepared.target,
        prepared_config=prepared.config,
    )
    record_audit_event(
        db,
        action="scanner.job.prepared",
        affected_object_type="scanner_job",
        affected_object_id=str(job.id),
        result="success",
        metadata={
            "adapter_name": job.adapter_name,
            "target": job.target,
            "organization_id": job.organization_id,
            "scope_id": job.scope_id,
        },
    )
    db.commit()
    db.refresh(job)
    return job


@router.get("", response_model=list[ScannerJobRead])
def list_all(
    organization_id: int | None = None,
    adapter_name: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[ScannerJobRead]:
    return list_scanner_jobs(db, organization_id=organization_id, adapter_name=adapter_name)


@router.get("/{job_id}", response_model=ScannerJobRead)
def get(job_id: int, db: Session = Depends(get_db)) -> ScannerJobRead:
    job = get_scanner_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scanner job not found")
    return job

