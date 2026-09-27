from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.assets import get_asset
from app.repositories.services import get_service, list_service_observations, list_services, observe_service
from app.schemas.service import ServiceObservationRead, ServiceObserve, ServiceRead, ServiceUpdate
from app.services.audit import record_audit_event

router = APIRouter(prefix="/services", tags=["services"])


@router.post("", response_model=ServiceRead, status_code=status.HTTP_201_CREATED)
def observe(payload: ServiceObserve, db: Session = Depends(get_db)) -> ServiceRead:
    if get_asset(db, payload.asset_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    service, created = observe_service(
        db,
        asset_id=payload.asset_id,
        protocol=payload.protocol,
        port=payload.port,
        name=payload.name,
        source=payload.source,
        metadata=payload.metadata,
    )
    record_audit_event(
        db,
        action="service.created" if created else "service.observed",
        affected_object_type="service",
        affected_object_id=str(service.id),
        result="success",
        metadata={"asset_id": payload.asset_id, "protocol": service.protocol.value, "port": service.port},
    )
    db.commit()
    db.refresh(service)
    return service


@router.get("", response_model=list[ServiceRead])
def list_all(
    asset_id: int | None = None,
    active: bool | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[ServiceRead]:
    return list_services(db, asset_id=asset_id, active=active)


@router.get("/{service_id}", response_model=ServiceRead)
def get(service_id: int, db: Session = Depends(get_db)) -> ServiceRead:
    service = get_service(db, service_id)
    if service is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
    return service


@router.patch("/{service_id}", response_model=ServiceRead)
def update(service_id: int, payload: ServiceUpdate, db: Session = Depends(get_db)) -> ServiceRead:
    service = get_service(db, service_id)
    if service is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    changed: dict[str, object] = {}
    if payload.active is not None:
        service.active = payload.active
        changed["active"] = service.active
    if payload.name is not None:
        service.name = payload.name
        changed["name"] = service.name

    record_audit_event(
        db,
        action="service.changed",
        affected_object_type="service",
        affected_object_id=str(service.id),
        result="success",
        metadata={"changed": changed},
    )
    db.commit()
    db.refresh(service)
    return service


@router.get("/{service_id}/observations", response_model=list[ServiceObservationRead])
def history(service_id: int, db: Session = Depends(get_db)) -> list[ServiceObservationRead]:
    if get_service(db, service_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
    return list_service_observations(db, service_id)

