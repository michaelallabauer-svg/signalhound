from datetime import datetime
from typing import Any, Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.asset import Asset
from app.models.risk import RiskSnapshot
from app.risk.engine import VERSION
from app.risk.service import create_snapshot

router = APIRouter(prefix='/assets/{asset_id}/risk', tags=['exposure and risk'])


class CalculateRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    organization_id: int = Field(gt=0)
    exposure: Literal['UNKNOWN', 'INTERNAL', 'INTERNET'] = 'UNKNOWN'
    criticality: Literal['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] = 'UNKNOWN'
    rationale: str = Field(default='', max_length=2000)

    @model_validator(mode='after')
    def contextual_evidence(self):
        self.rationale = self.rationale.strip()
        if (self.exposure != 'UNKNOWN' or self.criticality != 'UNKNOWN') and len(self.rationale) < 10:
            raise ValueError('Explain the exposure/criticality assumption in at least 10 characters.')
        return self


class SnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int
    created_at: datetime
    algorithm_version: str
    context: dict[str, Any]
    result: dict[str, Any]


class HistoryRead(BaseModel):
    algorithm_version: str
    snapshots: list[SnapshotRead]
    limit: int
    offset: int


def asset_for_org(db, asset_id, organization_id):
    asset = db.get(Asset, asset_id)
    if asset is None or asset.organization_id != organization_id:
        raise HTTPException(404, 'Asset not found in organization')
    return asset


@router.get('', response_model=HistoryRead)
def history(asset_id: int, organization_id: int = Query(gt=0), limit: int = Query(10, ge=1, le=50),
            offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    asset_for_org(db, asset_id, organization_id)
    rows = list(db.scalars(select(RiskSnapshot).where(RiskSnapshot.asset_id == asset_id)
                          .order_by(RiskSnapshot.id.desc()).offset(offset).limit(limit)))
    return {'algorithm_version': VERSION, 'snapshots': rows, 'offset': offset, 'limit': limit}


@router.post('', response_model=SnapshotRead, status_code=201)
def calculate(asset_id: int, payload: CalculateRequest, db: Session = Depends(get_db)):
    asset = asset_for_org(db, asset_id, payload.organization_id)
    try:
        return create_snapshot(db, asset, payload.model_dump(exclude={'organization_id'}))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
