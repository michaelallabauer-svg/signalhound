from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetObservation, AssetType


def observe_asset(
    db: Session,
    *,
    organization_id: int,
    asset_type: AssetType,
    value: str,
    source: str,
    scope_id: int | None,
    known_asset: bool,
    metadata: dict[str, Any],
) -> tuple[Asset, bool]:
    statement = (
        select(Asset)
        .where(Asset.organization_id == organization_id)
        .where(Asset.asset_type == asset_type)
        .where(Asset.value == value)
    )
    asset = db.scalar(statement)
    created = asset is None
    now = datetime.now(UTC)

    if asset is None:
        asset = Asset(
            organization_id=organization_id,
            asset_type=asset_type,
            value=value,
            source=source,
            scope_id=scope_id,
            known_asset=known_asset,
            active=True,
            first_seen=now,
            last_seen=now,
        )
        db.add(asset)
        db.flush()
    else:
        asset.last_seen = now
        asset.active = True
        asset.source = source
        asset.known_asset = asset.known_asset or known_asset
        if scope_id is not None:
            asset.scope_id = scope_id

    db.add(AssetObservation(asset_id=asset.id, source=source, metadata_=metadata))
    db.flush()
    return asset, created


def list_assets(
    db: Session,
    *,
    organization_id: int | None = None,
    scope_id: int | None = None,
    active: bool | None = None,
) -> list[Asset]:
    statement = select(Asset).order_by(Asset.id)
    if organization_id is not None:
        statement = statement.where(Asset.organization_id == organization_id)
    if scope_id is not None:
        statement = statement.where(Asset.scope_id == scope_id)
    if active is not None:
        statement = statement.where(Asset.active == active)
    return list(db.scalars(statement))


def get_asset(db: Session, asset_id: int) -> Asset | None:
    return db.get(Asset, asset_id)


def list_asset_observations(db: Session, asset_id: int) -> list[AssetObservation]:
    statement = (
        select(AssetObservation)
        .where(AssetObservation.asset_id == asset_id)
        .order_by(AssetObservation.observed_at, AssetObservation.id)
    )
    return list(db.scalars(statement))

