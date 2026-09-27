from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.organizations import create_organization, get_organization, list_organizations
from app.schemas.organization import OrganizationCreate, OrganizationRead
from app.services.audit import record_audit_event

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post("", response_model=OrganizationRead, status_code=status.HTTP_201_CREATED)
def create(payload: OrganizationCreate, db: Session = Depends(get_db)) -> OrganizationRead:
    try:
        organization = create_organization(db, payload.name)
        record_audit_event(
            db,
            action="organization.created",
            affected_object_type="organization",
            affected_object_id=str(organization.id),
            result="success",
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization already exists",
        ) from exc

    db.refresh(organization)
    return organization


@router.get("", response_model=list[OrganizationRead])
def list_all(db: Session = Depends(get_db)) -> list[OrganizationRead]:
    return list_organizations(db)


@router.get("/{organization_id}", response_model=OrganizationRead)
def get(organization_id: int, db: Session = Depends(get_db)) -> OrganizationRead:
    organization = get_organization(db, organization_id)
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return organization

