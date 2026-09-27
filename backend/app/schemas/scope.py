from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.scope import ScanZone, ScopeTargetType


class ScopeCreate(BaseModel):
    organization_id: int
    name: str = Field(min_length=1, max_length=255)
    target_type: ScopeTargetType
    target: str = Field(min_length=1, max_length=255)
    scan_zone: ScanZone = ScanZone.EXTERNAL

    @model_validator(mode="after")
    def external_only(self) -> "ScopeCreate":
        if self.scan_zone != ScanZone.EXTERNAL:
            raise ValueError("Only EXTERNAL scan zone is supported in MVP V1")
        return self


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

    @model_validator(mode="after")
    def external_only(self) -> "ScopeValidationRequest":
        if self.scan_zone != ScanZone.EXTERNAL:
            raise ValueError("Only EXTERNAL scan zone is supported in MVP V1")
        return self


class ScopeValidationResponse(BaseModel):
    target: str
    normalized_target: str
    allowed: bool
    scope_id: int | None
    reason: str

