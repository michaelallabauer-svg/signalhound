from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.scope import ScanZone, ScopeTargetType


class ScopeCreate(BaseModel):
    organization_id: int
    name: str = Field(min_length=1, max_length=255)
    target_type: ScopeTargetType
    target: str = Field(min_length=1, max_length=255)
    scan_zone: ScanZone = ScanZone.EXTERNAL


class ScopeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    active: bool | None = None


class ScopeRead(BaseModel):
    id: int
    organization_id: int
    name: str
    target_type: ScopeTargetType
    target: str
    scan_zone: ScanZone
    active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScopeValidationRequest(BaseModel):
    organization_id: int
    target: str = Field(min_length=1, max_length=255)
    scan_zone: ScanZone = ScanZone.EXTERNAL


class ScopeValidationResponse(BaseModel):
    target: str
    normalized_target: str
    allowed: bool
    scope_id: int | None
    reason: str
