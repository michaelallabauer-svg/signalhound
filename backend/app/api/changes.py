from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.changes import get_change_set, list_change_events, list_change_sets
from app.repositories.organizations import get_organization
from app.schemas.change import ChangeDetectionRequest, ChangeEventRead, ChangeSetDetail, ChangeSetRead
from app.services.audit import record_audit_event
from app.services.change_detection import detect_changes

router = APIRouter(prefix="/change-sets", tags=["change-detection"])


@router.post("/compare", response_model=ChangeSetDetail, status_code=status.HTTP_201_CREATED)
def compare(payload: ChangeDetectionRequest, db: Session = Depends(get_db)) -> ChangeSetDetail:
    if get_organization(db, payload.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    change_set = detect_changes(
        db,
        organization_id=payload.organization_id,
        baseline_at=payload.baseline_at,
        comparison_at=payload.comparison_at,
    )
    record_audit_event(
        db,
        action="change_set.created",
        affected_object_type="change_set",
        affected_object_id=str(change_set.id),
        result="success",
        metadata={"summary": change_set.summary},
    )
    db.commit()
    db.refresh(change_set)
    events = list_change_events(db, change_set.id)
    return ChangeSetDetail.model_validate({**change_set.__dict__, "events": events})


@router.get("", response_model=list[ChangeSetRead])
def list_all(organization_id: int | None = None, db: Session = Depends(get_db)) -> list[ChangeSetRead]:
    return list_change_sets(db, organization_id=organization_id)


@router.get("/{change_set_id}", response_model=ChangeSetDetail)
def get(change_set_id: int, db: Session = Depends(get_db)) -> ChangeSetDetail:
    change_set = get_change_set(db, change_set_id)
    if change_set is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change set not found")
    events = list_change_events(db, change_set.id)
    return ChangeSetDetail.model_validate({**change_set.__dict__, "events": events})


@router.get("/{change_set_id}/events", response_model=list[ChangeEventRead])
def events(change_set_id: int, db: Session = Depends(get_db)) -> list[ChangeEventRead]:
    if get_change_set(db, change_set_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change set not found")
    return list_change_events(db, change_set_id)
