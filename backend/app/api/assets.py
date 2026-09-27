from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scope import ScanZone
from app.repositories.assets import get_asset, list_asset_observations, list_assets, observe_asset
from app.repositories.organizations import get_organization
from app.repositories.scopes import get_scope
from app.schemas.asset import AssetObservationRead, AssetObserve, AssetRead, AssetUpdate
from app.services.asset_normalization import normalize_asset_value
from app.services.audit import record_audit_event
from app.services.scope_validation import ScopeValidator

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def observe(payload: AssetObserve, db: Session = Depends(get_db)) -> AssetRead:
    if get_organization(db, payload.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    if payload.scope_id is not None:
        scope = get_scope(db, payload.scope_id)
        if scope is None or scope.organization_id != payload.organization_id or not scope.active:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active scope not found")

    try:
        value = normalize_asset_value(payload.value, payload.asset_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Asset value is invalid for the selected asset type") from exc

    if payload.scope_id is not None:
        validation = ScopeValidator().validate(
            db,
            organization_id=payload.organization_id,
            target=value,
            scan_zone=ScanZone.EXTERNAL,
        )
        if not validation.allowed or validation.scope_id != payload.scope_id:
            db.rollback()
            raise HTTPException(status_code=403, detail="Asset value is not authorized by the provided scope")

    asset, created = observe_asset(
        db,
        organization_id=payload.organization_id,
        asset_type=payload.asset_type,
        value=value,
        source=payload.source,
        scope_id=payload.scope_id,
        known_asset=payload.known_asset,
        metadata=payload.metadata,
    )
    record_audit_event(
        db,
        action="asset.created" if created else "asset.observed",
        affected_object_type="asset",
        affected_object_id=str(asset.id),
        result="success",
        metadata={"asset_type": asset.asset_type.value, "value": asset.value, "source": payload.source},
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.get("", response_model=list[AssetRead])
def list_all(
    organization_id: int | None = None,
    scope_id: int | None = None,
    active: bool | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[AssetRead]:
    return list_assets(db, organization_id=organization_id, scope_id=scope_id, active=active)


@router.get("/{asset_id}", response_model=AssetRead)
def get(asset_id: int, db: Session = Depends(get_db)) -> AssetRead:
    asset = get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetRead)
def update(asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db)) -> AssetRead:
    asset = get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    changed: dict[str, object] = {}
    if payload.active is not None:
        asset.active = payload.active
        changed["active"] = asset.active
    if payload.known_asset is not None:
        asset.known_asset = payload.known_asset
        changed["known_asset"] = asset.known_asset

    record_audit_event(
        db,
        action="asset.changed",
        affected_object_type="asset",
        affected_object_id=str(asset.id),
        result="success",
        metadata={"changed": changed},
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}/observations", response_model=list[AssetObservationRead])
def history(asset_id: int, db: Session = Depends(get_db)) -> list[AssetObservationRead]:
    if get_asset(db, asset_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return list_asset_observations(db, asset_id)

