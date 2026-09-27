from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.organization import Organization


def create_organization(db: Session, name: str) -> Organization:
    organization = Organization(name=name.strip())
    db.add(organization)
    db.flush()
    return organization


def list_organizations(db: Session) -> list[Organization]:
    return list(db.scalars(select(Organization).order_by(Organization.name)))


def get_organization(db: Session, organization_id: int) -> Organization | None:
    return db.get(Organization, organization_id)

