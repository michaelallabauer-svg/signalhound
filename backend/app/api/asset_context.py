from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.asset_context import AssetContextHistory, Site
from app.models.organization import Organization
from app.schemas.asset_context import ContextRead, ContextUpdate, HistoryRead, SiteCreate, SiteRead, SiteUpdate
from app.services.asset_context import owned_asset, read_context, update_context
from app.services.audit import record_audit_event

router = APIRouter(tags=['asset business context'])


@router.get('/assets/{asset_id}/context', response_model=ContextRead)
def context(asset_id: int, organization_id: int = Query(gt=0), db: Session = Depends(get_db)):
    return read_context(db, owned_asset(db, asset_id, organization_id))


@router.patch('/assets/{asset_id}/context', response_model=ContextRead)
def save_context(asset_id: int, payload: ContextUpdate, db: Session = Depends(get_db)):
    return update_context(db, asset_id, payload)


@router.get('/assets/{asset_id}/context/history', response_model=list[HistoryRead])
def history(asset_id: int, organization_id: int = Query(gt=0), limit: int = Query(20, ge=1, le=100),
            offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    owned_asset(db, asset_id, organization_id)
    return list(db.scalars(select(AssetContextHistory).where(AssetContextHistory.asset_id == asset_id)
                          .order_by(AssetContextHistory.revision.desc()).offset(offset).limit(limit)))


def organization(db, organization_id):
    if db.get(Organization, organization_id) is None:
        raise HTTPException(404, 'Organization not found')


@router.get('/sites', response_model=list[SiteRead])
def sites(organization_id: int = Query(gt=0), active: bool | None = None, db: Session = Depends(get_db)):
    organization(db, organization_id)
    query = select(Site).where(Site.organization_id == organization_id).order_by(Site.name_key, Site.id)
    if active is not None:
        query = query.where(Site.active == active)
    return list(db.scalars(query))


def flush_site(db):
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, 'A location with this name already exists in this organization, possibly archived.') from exc


@router.post('/sites', response_model=SiteRead, status_code=201)
def create_site(payload: SiteCreate, db: Session = Depends(get_db)):
    organization(db, payload.organization_id)
    site = Site(**payload.model_dump(), name_key=payload.name.casefold(), active=True, revision=1)
    db.add(site)
    flush_site(db)
    record_audit_event(db, action='site.created', affected_object_type='site', affected_object_id=str(site.id),
                       result='success', metadata={'after':SiteRead.model_validate(site).model_dump(mode='json')})
    db.commit(); db.refresh(site)
    return site


@router.patch('/sites/{site_id}', response_model=SiteRead)
def change_site(site_id: int, payload: SiteUpdate, db: Session = Depends(get_db)):
    site = db.scalar(select(Site).where(Site.id == site_id, Site.organization_id == payload.organization_id).with_for_update())
    if site is None:
        raise HTTPException(404, 'Location not found in organization')
    if site.revision != payload.expected_revision:
        raise HTTPException(409, 'Location changed elsewhere. Reload locations before saving again.')
    before = SiteRead.model_validate(site).model_dump(mode='json')
    changes = payload.model_dump(exclude_unset=True, exclude={'organization_id', 'expected_revision'})
    if all(getattr(site, name) == value for name, value in changes.items()):
        return site
    for name, value in changes.items():
        setattr(site, name, value)
    site.name_key = site.name.casefold()
    site.revision += 1
    site.updated_at = datetime.now(timezone.utc)
    flush_site(db)
    record_audit_event(db, action='site.changed', affected_object_type='site', affected_object_id=str(site.id), result='success',
                       metadata={'before':before, 'after':SiteRead.model_validate(site).model_dump(mode='json')})
    db.commit(); db.refresh(site)
    return site
