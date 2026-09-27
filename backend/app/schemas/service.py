from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.service import ServiceProtocol


class ServiceObserve(BaseModel):
    asset_id: int
    protocol: ServiceProtocol
    port: int = Field(ge=1, le=65535)
    source: str = Field(min_length=1, max_length=120)
    name: str | None = Field(default=None, max_length=120)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ServiceUpdate(BaseModel):
    active: bool | None = None
    name: str | None = Field(default=None, max_length=120)


class ServiceRead(BaseModel):
    id: int
    asset_id: int
    protocol: ServiceProtocol
    port: int
    name: str | None
    source: str
    first_seen: datetime
    last_seen: datetime
    active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ServiceObservationRead(BaseModel):
    id: int
    service_id: int
    observed_at: datetime
    source: str
    metadata_: dict[str, Any] = Field(serialization_alias="metadata")

    model_config = ConfigDict(from_attributes=True)

