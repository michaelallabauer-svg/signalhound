from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingSeverity, FindingStatus


class FindingCreate(BaseModel):
    organization_id: int
    asset_id: int
    service_id: int | None = None
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: FindingSeverity
    source: str = Field(min_length=1, max_length=120)
    external_reference: str | None = Field(default=None, max_length=255)
    remediation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    remediation: str | None = None


class FindingRead(BaseModel):
    id: int
    organization_id: int
    asset_id: int
    service_id: int | None
    title: str
    description: str | None
    severity: FindingSeverity
    source: str
    external_reference: str | None
    status: FindingStatus
    remediation: str | None
    evidence: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingObservationRead(BaseModel):
    id: int
    finding_id: int
    observed_at: datetime
    source: str
    evidence: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)

