from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.organizations import get_organization
from app.repositories.scopes import create_scope, get_scope, list_scopes
from app.schemas.scope import (
    ScopeCreate,
    ScopeRead,
    ScopeUpdate,
    ScopeValidationRequest,
    ScopeValidationResponse,
)
from app.services.audit import record_audit_event
from app.services.scope_normalization import normalize_target
from app.services.scope_validation import ScopeValidator

router = APIRouter(prefix="/scopes", tags=["scopes"])


@router.post("", response_model=ScopeRead, status_code=status.HTTP_201_CREATED)
def create(payload: ScopeCreate, db: Session = Depends(get_db)) -> ScopeRead:
    if get_organization(db, payload.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    try:
        normalized_target = normalize_target(payload.target, payload.target_type)
        scope = create_scope(
            db,
            organization_id=payload.organization_id,
            name=payload.name,
            target_type=payload.target_type,
            target=normalized_target,
            scan_zone=payload.scan_zone,
        )
        record_audit_event(
            db,
            action="scope.created",
            affected_object_type="scope",
            affected_object_id=str(scope.id),
            result="success",
            metadata={"target": scope.target, "target_type": scope.target_type.value},
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail="Scope target is invalid for the selected target type",
        ) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scope could not be created",
        ) from exc

    db.refresh(scope)
    return scope


@router.get("", response_model=list[ScopeRead])
def list_all(
    organization_id: int | None = None,
    active: bool | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[ScopeRead]:
    return list_scopes(db, organization_id=organization_id, active=active)


@router.get("/{scope_id}", response_model=ScopeRead)
def get(scope_id: int, db: Session = Depends(get_db)) -> ScopeRead:
    scope = get_scope(db, scope_id)
    if scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
    return scope


@router.patch("/{scope_id}", response_model=ScopeRead)
def update(scope_id: int, payload: ScopeUpdate, db: Session = Depends(get_db)) -> ScopeRead:
    scope = get_scope(db, scope_id)
    if scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")

    changed: dict[str, object] = {}
    if payload.name is not None:
        scope.name = payload.name.strip()
        changed["name"] = scope.name
    if payload.active is not None:
        scope.active = payload.active
        changed["active"] = scope.active

    record_audit_event(
        db,
        action="scope.changed",
        affected_object_type="scope",
        affected_object_id=str(scope.id),
        result="success",
        metadata={"changed": changed},
    )
    db.commit()
    db.refresh(scope)
    return scope


@router.delete("/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete(scope_id: int, db: Session = Depends(get_db)) -> None:
    scope = get_scope(db, scope_id)
    if scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")

    scope.active = False
    record_audit_event(
        db,
        action="scope.deleted",
        affected_object_type="scope",
        affected_object_id=str(scope.id),
        result="success",
        metadata={"soft_delete": True},
    )
    db.commit()


@router.post("/validate", response_model=ScopeValidationResponse)
def validate(payload: ScopeValidationRequest, db: Session = Depends(get_db)) -> ScopeValidationResponse:
    if get_organization(db, payload.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    result = ScopeValidator().validate(
        db,
        organization_id=payload.organization_id,
        target=payload.target,
        scan_zone=payload.scan_zone,
    )
    db.commit()
    return ScopeValidationResponse(**result.__dict__)
