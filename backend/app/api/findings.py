from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.finding import FindingSeverity, FindingStatus
from app.repositories.assets import get_asset
from app.repositories.findings import get_finding, list_finding_observations, list_findings, observe_finding
from app.repositories.organizations import get_organization
from app.repositories.services import get_service
from app.schemas.finding import FindingCreate, FindingObservationRead, FindingRead, FindingStatusUpdate
from app.services.audit import record_audit_event

router = APIRouter(prefix="/findings", tags=["findings"])


@router.post("", response_model=FindingRead, status_code=status.HTTP_201_CREATED)
def create(payload: FindingCreate, db: Session = Depends(get_db)) -> FindingRead:
    if get_organization(db, payload.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    asset = get_asset(db, payload.asset_id)
    if asset is None or asset.organization_id != payload.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    if payload.service_id is not None:
        service = get_service(db, payload.service_id)
        if service is None or service.asset_id != payload.asset_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    finding, created = observe_finding(
        db,
        organization_id=payload.organization_id,
        asset_id=payload.asset_id,
        service_id=payload.service_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        source=payload.source,
        external_reference=payload.external_reference,
        remediation=payload.remediation,
        evidence=payload.evidence,
    )
    record_audit_event(
        db,
        action="finding.created" if created else "finding.observed",
        affected_object_type="finding",
        affected_object_id=str(finding.id),
        result="success",
        metadata={"source": finding.source, "severity": finding.severity.value, "status": finding.status.value},
    )
    db.commit()
    db.refresh(finding)
    return finding


@router.get("", response_model=list[FindingRead])
def list_all(
    organization_id: int | None = None,
    asset_id: int | None = None,
    service_id: int | None = None,
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    severity: FindingSeverity | None = None,
    db: Session = Depends(get_db),
) -> list[FindingRead]:
    return list_findings(
        db,
        organization_id=organization_id,
        asset_id=asset_id,
        service_id=service_id,
        status=status_filter,
        severity=severity,
    )


@router.get("/{finding_id}", response_model=FindingRead)
def get(finding_id: int, db: Session = Depends(get_db)) -> FindingRead:
    finding = get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingRead)
def update_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
) -> FindingRead:
    finding = get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    old_status = finding.status
    finding.status = payload.status
    if payload.remediation is not None:
        finding.remediation = payload.remediation
    record_audit_event(
        db,
        action="finding.status.changed",
        affected_object_type="finding",
        affected_object_id=str(finding.id),
        result="success",
        metadata={"from": old_status.value, "to": finding.status.value},
    )
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/{finding_id}/observations", response_model=list[FindingObservationRead])
def history(finding_id: int, db: Session = Depends(get_db)) -> list[FindingObservationRead]:
    if get_finding(db, finding_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return list_finding_observations(db, finding_id)

