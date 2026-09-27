from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.scanner_job import ScannerJobStatus


class ScannerAdapterRead(BaseModel):
    name: str
    display_name: str
    supported_target_notes: str
    execution_available: bool = False


class ScannerJobCreate(BaseModel):
    organization_id: int
    scope_id: int
    adapter_name: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=255)


class ScannerJobRead(BaseModel):
    id: int
    organization_id: int
    scope_id: int
    adapter_name: str
    target: str
    status: ScannerJobStatus
    prepared_config: dict[str, Any]
    raw_output: str | None
    normalized_result: dict[str, Any] | None
    error_message: str | None
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

