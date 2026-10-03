"""Analyst-maintained business context, isolated from scanner observations."""
from datetime import datetime
from typing import Any
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class Site(Base):
    __tablename__ = 'sites'
    __table_args__ = (UniqueConstraint('organization_id', 'name_key', name='uq_sites_org_name'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey('organizations.id'), index=True)
    name: Mapped[str] = mapped_column(String(160))
    name_key: Mapped[str] = mapped_column(String(640))
    description: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssetBusinessContext(Base):
    __tablename__ = 'asset_business_contexts'
    __table_args__ = (
        CheckConstraint("criticality IS NULL OR criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')", name='ck_asset_context_criticality'),
        CheckConstraint("environment IN ('PRODUCTION','TEST','DEVELOPMENT','INFRASTRUCTURE','UNKNOWN')", name='ck_asset_context_environment'),
    )
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), primary_key=True)
    criticality: Mapped[str | None] = mapped_column(String(20))
    environment: Mapped[str] = mapped_column(String(20), default='UNKNOWN')
    technical_owner: Mapped[str | None] = mapped_column(String(160))
    organizational_owner: Mapped[str | None] = mapped_column(String(160))
    responsible_team: Mapped[str | None] = mapped_column(String(160))
    site_id: Mapped[int | None] = mapped_column(ForeignKey('sites.id'), index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    revision: Mapped[int] = mapped_column(default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AssetContextHistory(Base):
    __tablename__ = 'asset_context_history'
    __table_args__ = (UniqueConstraint('asset_id', 'revision', name='uq_asset_context_revision'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('assets.id'), index=True)
    revision: Mapped[int] = mapped_column()
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    before: Mapped[dict[str, Any]] = mapped_column(JSON)
    after: Mapped[dict[str, Any]] = mapped_column(JSON)
