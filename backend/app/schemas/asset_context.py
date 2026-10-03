from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Criticality = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
Environment = Literal['PRODUCTION', 'TEST', 'DEVELOPMENT', 'INFRASTRUCTURE', 'UNKNOWN']


class ContextFields(BaseModel):
    model_config = ConfigDict(extra='forbid')
    criticality: Criticality | None = None
    environment: Environment = 'UNKNOWN'
    technical_owner: str | None = Field(default=None, max_length=160)
    organizational_owner: str | None = Field(default=None, max_length=160)
    responsible_team: str | None = Field(default=None, max_length=160)
    site_id: int | None = Field(default=None, gt=0)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator('technical_owner', 'organizational_owner', 'responsible_team', 'notes', mode='before')
    @classmethod
    def clean_optional(cls, value):
        return (value.strip() or None) if isinstance(value, str) else value


class ContextUpdate(ContextFields):
    organization_id: int = Field(gt=0)
    expected_revision: int = Field(ge=0)

    @model_validator(mode='after')
    def nonempty(self):
        if not (self.model_fields_set - {'organization_id', 'expected_revision'}):
            raise ValueError('Provide at least one context field to change.')
        return self


class SiteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    organization_id: int
    name: str
    description: str | None
    active: bool
    revision: int
    created_at: datetime
    updated_at: datetime

    @field_validator('created_at', 'updated_at')
    @classmethod
    def utc_dates(cls, value):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class ContextRead(ContextFields):
    asset_id: int
    organization_id: int
    revision: int
    updated_at: datetime | None
    site: SiteRead | None

    @field_validator('updated_at')
    @classmethod
    def utc_date(cls, value):
        return SiteRead.utc_dates(value) if value is not None else None


class HistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int
    revision: int
    changed_at: datetime
    before: dict[str, Any]
    after: dict[str, Any]

    @field_validator('changed_at')
    @classmethod
    def utc_date(cls, value):
        return SiteRead.utc_dates(value)


class SiteCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    organization_id: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator('name', mode='before')
    @classmethod
    def clean_name(cls, value):
        return ' '.join(value.split()) if isinstance(value, str) else value

    @field_validator('description', mode='before')
    @classmethod
    def clean_description(cls, value):
        return (value.strip() or None) if isinstance(value, str) else value


class SiteUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    organization_id: int = Field(gt=0)
    expected_revision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None
    clean_name = field_validator('name', mode='before')(SiteCreate.clean_name.__func__)
    clean_description = field_validator('description', mode='before')(SiteCreate.clean_description.__func__)

    @model_validator(mode='after')
    def validate_patch(self):
        fields = self.model_fields_set - {'organization_id', 'expected_revision'}
        if not fields or ('name' in fields and self.name is None) or ('active' in fields and self.active is None):
            raise ValueError('Supply changes; name and active cannot be null.')
        return self
