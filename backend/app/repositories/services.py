from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.service import Service, ServiceObservation, ServiceProtocol


def observe_service(
    db: Session,
    *,
    asset_id: int,
    protocol: ServiceProtocol,
    port: int,
    name: str | None,
    source: str,
    metadata: dict[str, Any],
) -> tuple[Service, bool]:
    statement = (
        select(Service)
        .where(Service.asset_id == asset_id)
        .where(Service.protocol == protocol)
        .where(Service.port == port)
    )
    service = db.scalar(statement)
    created = service is None
    now = datetime.now(UTC)

    if service is None:
        service = Service(
            asset_id=asset_id,
            protocol=protocol,
            port=port,
            name=name,
            source=source,
            active=True,
            first_seen=now,
            last_seen=now,
        )
        db.add(service)
        db.flush()
    else:
        service.last_seen = now
        service.active = True
        service.source = source
        if name is not None:
            service.name = name

    db.add(ServiceObservation(service_id=service.id, source=source, metadata_=metadata))
    db.flush()
    return service, created


def list_services(
    db: Session,
    *,
    asset_id: int | None = None,
    active: bool | None = None,
) -> list[Service]:
    statement = select(Service).order_by(Service.id)
    if asset_id is not None:
        statement = statement.where(Service.asset_id == asset_id)
    if active is not None:
        statement = statement.where(Service.active == active)
    return list(db.scalars(statement))


def get_service(db: Session, service_id: int) -> Service | None:
    return db.get(Service, service_id)


def list_service_observations(db: Session, service_id: int) -> list[ServiceObservation]:
    statement = (
        select(ServiceObservation)
        .where(ServiceObservation.service_id == service_id)
        .order_by(ServiceObservation.observed_at, ServiceObservation.id)
    )
    return list(db.scalars(statement))

