from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.intelligence.service import enrich, evidence_inputs
from app.models.asset import Asset
from app.models.intelligence import IntelligenceRun

router = APIRouter(prefix="/assets/{asset_id}/intelligence", tags=["vulnerability intelligence"])


class EnrichRequest(BaseModel):
    organization_id: int = Field(gt=0)
    evidence_key: str = Field(min_length=1, max_length=650)


class RunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int
    created_at: datetime
    status: str
    evidence: dict[str, Any]
    result: dict[str, Any]


class IntelligenceRead(BaseModel):
    enabled: bool
    software: list[dict[str, Any]]
    inputs: list[dict[str, Any]]
    runs: list[RunRead]
    limit: int
    offset: int


def check_asset(db: Session, asset_id: int, organization_id: int):
    asset = db.get(Asset, asset_id)
    if asset is None or asset.organization_id != organization_id:
        raise HTTPException(404, "Asset not found in organization")


@router.get("", response_model=IntelligenceRead)
def read(asset_id: int, organization_id: int = Query(gt=0), limit: int = Query(20, ge=1, le=100),
         offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    check_asset(db, asset_id, organization_id)
    return {"enabled": get_settings().intelligence_enabled, **evidence_inputs(db, asset_id),
            "runs": list(db.scalars(select(IntelligenceRun).where(IntelligenceRun.asset_id == asset_id)
                                    .order_by(IntelligenceRun.id.desc()).limit(limit).offset(offset))),
            "limit": limit, "offset": offset}


@router.post("", response_model=RunRead, status_code=201)
def create(asset_id: int, payload: EnrichRequest, db: Session = Depends(get_db)):
    check_asset(db, asset_id, payload.organization_id)
    if not get_settings().intelligence_enabled:
        raise HTTPException(409, "Intelligence lookup is disabled. Enable INTELLIGENCE_ENABLED on the backend.")
    evidence = next((item for item in evidence_inputs(db, asset_id)["inputs"] if item["key"] == payload.evidence_key), None)
    if evidence is None:
        raise HTTPException(422, "Select an existing CVE reference or an observed, version-specific CPE for this asset.")
    return enrich(db, asset_id, evidence)
