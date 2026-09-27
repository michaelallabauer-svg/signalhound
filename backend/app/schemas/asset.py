from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.asset import AssetType
from app.schemas.finding import FindingRead
from app.schemas.service import ServiceObservationRead, ServiceRead


class AssetObserve(BaseModel):
    organization_id: int
    asset_type: AssetType
    value: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=120)
    scope_id: int | None = None
    known_asset: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    active: bool | None = None
    known_asset: bool | None = None


class AssetRead(BaseModel):
    id: int
    organization_id: int
    scope_id: int | None
    asset_type: AssetType
    value: str
    source: str
    first_seen: datetime
    last_seen: datetime
    active: bool
    known_asset: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetObservationRead(BaseModel):
    id: int
    asset_id: int
    observed_at: datetime
    source: str
    metadata_: dict[str, Any] = Field(serialization_alias="metadata")

    model_config = ConfigDict(from_attributes=True)


class AssetDetailRead(AssetRead):
    observations: list[AssetObservationRead]
    services: list[ServiceRead]
    service_observations: list[ServiceObservationRead]
    findings: list[FindingRead]
