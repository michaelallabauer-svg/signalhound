from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy import select
from app.models.asset import Asset
from app.models.asset_context import AssetBusinessContext, AssetContextHistory, Site
from app.schemas.asset_context import ContextFields, ContextRead, SiteRead
from app.services.audit import record_audit_event


def owned_asset(db, asset_id, organization_id, lock=False):
    query = select(Asset).where(Asset.id == asset_id, Asset.organization_id == organization_id)
    asset = db.scalar(query.with_for_update() if lock else query)
    if asset is None:
        raise HTTPException(404, 'Asset not found in organization')
    return asset


def read_context(db, asset):
    context = db.get(AssetBusinessContext, asset.id)
    fields = {name: getattr(context, name) for name in ContextFields.model_fields} if context else ContextFields().model_dump()
    site = db.get(Site, fields['site_id']) if fields['site_id'] else None
    return ContextRead(**fields, asset_id=asset.id, organization_id=asset.organization_id,
                       revision=context.revision if context else 0, updated_at=context.updated_at if context else None,
                       site=SiteRead.model_validate(site) if site else None)


def update_context(db, asset_id, payload):
    # Parent lock serializes creation too, when the one-to-one context row is still absent.
    asset = owned_asset(db, asset_id, payload.organization_id, lock=True)
    before = read_context(db, asset)
    if before.revision != payload.expected_revision:
        raise HTTPException(409, 'Asset context changed elsewhere. Reload the current context before saving again.')
    changes = payload.model_dump(exclude_unset=True, exclude={'organization_id', 'expected_revision'})
    site_id = changes.get('site_id')
    if site_id is not None:
        site = db.scalar(select(Site).where(Site.id == site_id, Site.organization_id == asset.organization_id).with_for_update().execution_options(populate_existing=True))
        if site is None:
            raise HTTPException(404, 'Location not found in organization')
        if not site.active and before.site_id != site.id:
            raise HTTPException(422, 'Archived locations cannot receive new assignments. Restore the location first.')
    if all(getattr(before, name) == value for name, value in changes.items()):
        return before
    changes = {name: value for name, value in changes.items() if getattr(before, name) != value}
    context = db.get(AssetBusinessContext, asset.id)
    if context is None:
        context = AssetBusinessContext(asset_id=asset.id, **ContextFields().model_dump())
        db.add(context)
    for name, value in changes.items():
        setattr(context, name, value)
    context.revision = before.revision + 1
    context.updated_at = datetime.now(timezone.utc)
    db.flush()
    after = read_context(db, asset)
    db.add(AssetContextHistory(asset_id=asset.id, revision=context.revision, changed_at=context.updated_at,
                               before=before.model_dump(mode='json'), after=after.model_dump(mode='json')))
    record_audit_event(db, action='asset.context.changed', affected_object_type='asset', affected_object_id=str(asset.id),
                       result='success', metadata={'revision':context.revision, 'changed_fields':list(changes)})
    db.commit()
    return after
