from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.assessment import AssessmentRunStatus


class ScanProfileRead(BaseModel):
    name: str
    display_name: str
    description: str
    scan_zone: str
    adapter_sequence: tuple[str, ...]


class AssessmentRunCreate(BaseModel):
    organization_id: int
    scope_id: int
    profile_name: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=255)


class AssessmentRunRead(BaseModel):
    id: int
    organization_id: int
    scope_id: int
    profile_name: str
    target: str
    status: AssessmentRunStatus
    summary: dict[str, Any]
    error_message: str | None
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
