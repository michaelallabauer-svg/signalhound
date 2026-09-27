from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.change import ChangeEntityType, ChangeType


class ChangeDetectionRequest(BaseModel):
    organization_id: int
    baseline_at: datetime
    comparison_at: datetime

    @model_validator(mode="after")
    def validate_window(self) -> "ChangeDetectionRequest":
        if self.baseline_at >= self.comparison_at:
            raise ValueError("baseline_at must be before comparison_at")
        return self


class ChangeEventRead(BaseModel):
    id: int
    change_set_id: int
    entity_type: ChangeEntityType
    change_type: ChangeType
    entity_key: str
    object_id: int | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None

    model_config = ConfigDict(from_attributes=True)


class ChangeSetRead(BaseModel):
    id: int
    organization_id: int
    baseline_at: datetime
    comparison_at: datetime
    summary: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ChangeSetDetail(ChangeSetRead):
    events: list[ChangeEventRead]
