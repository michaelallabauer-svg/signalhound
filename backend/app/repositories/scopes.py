from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scope import ScanZone, Scope, ScopeTargetType


def create_scope(
    db: Session,
    *,
    organization_id: int,
    name: str,
    target_type: ScopeTargetType,
    target: str,
    scan_zone: ScanZone,
) -> Scope:
    scope = Scope(
        organization_id=organization_id,
        name=name.strip(),
        target_type=target_type,
        target=target,
        scan_zone=scan_zone,
    )
    db.add(scope)
    db.flush()
    return scope


def list_scopes(
    db: Session,
    *,
    organization_id: int | None = None,
    active: bool | None = None,
) -> list[Scope]:
    statement = select(Scope).order_by(Scope.id)
    if organization_id is not None:
        statement = statement.where(Scope.organization_id == organization_id)
    if active is not None:
        statement = statement.where(Scope.active == active)
    return list(db.scalars(statement))


def get_scope(db: Session, scope_id: int) -> Scope | None:
    return db.get(Scope, scope_id)

def find_active_scopes(
    db: Session,
    *,
    organization_id: int,
    scan_zone: ScanZone,
) -> list[Scope]:
    statement = (
        select(Scope)
        .where(Scope.organization_id == organization_id)
        .where(Scope.scan_zone == scan_zone)
        .where(Scope.active.is_(True))
        .order_by(Scope.id)
    )
    return list(db.scalars(statement))

