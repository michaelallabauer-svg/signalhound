from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.change import ChangeEvent, ChangeSet


def create_change_set(
    db: Session,
    *,
    change_set: ChangeSet,
    events: list[ChangeEvent],
) -> ChangeSet:
    db.add(change_set)
    db.flush()
    for event in events:
        event.change_set_id = change_set.id
        db.add(event)
    db.flush()
    return change_set


def get_change_set(db: Session, change_set_id: int) -> ChangeSet | None:
    return db.get(ChangeSet, change_set_id)


def list_change_sets(db: Session, *, organization_id: int | None = None) -> list[ChangeSet]:
    statement = select(ChangeSet).order_by(ChangeSet.created_at.desc(), ChangeSet.id.desc())
    if organization_id is not None:
        statement = statement.where(ChangeSet.organization_id == organization_id)
    return list(db.scalars(statement))


def list_change_events(db: Session, change_set_id: int) -> list[ChangeEvent]:
    statement = (
        select(ChangeEvent)
        .where(ChangeEvent.change_set_id == change_set_id)
        .order_by(ChangeEvent.entity_type, ChangeEvent.change_type, ChangeEvent.entity_key)
    )
    return list(db.scalars(statement))
