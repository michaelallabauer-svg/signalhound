"""Immutable expectations and independent point-in-time connectivity evidence."""
from datetime import datetime
from typing import Any
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class SegmentationRule(Base):
    __tablename__ = 'segmentation_rules'
    __table_args__ = (
        CheckConstraint("expected IN ('ALLOW','DENY')", name='ck_segmentation_expected'),
        CheckConstraint('port >= 1 AND port <= 65535', name='ck_segmentation_port'),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey('organizations.id'), index=True)
    name: Mapped[str] = mapped_column(String(160))
    source_id: Mapped[str] = mapped_column(String(80))
    source: Mapped[dict[str, Any]] = mapped_column(JSON)
    scope_id: Mapped[int] = mapped_column(ForeignKey('scopes.id'))
    zone: Mapped[dict[str, Any]] = mapped_column(JSON)
    target: Mapped[str] = mapped_column(String(45))
    port: Mapped[int]
    expected: Mapped[str] = mapped_column(String(10))
    rationale: Mapped[str] = mapped_column(String(2000))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SegmentationCheck(Base):
    __tablename__ = 'segmentation_checks'
    __table_args__ = (
        CheckConstraint("status IN ('PASS','FAIL','NOT_TESTED','ERROR')", name='ck_segmentation_status'),
        CheckConstraint("outcome IN ('PASS','UNEXPECTED_ACCESS','UNEXPECTED_BLOCK','NOT_TESTED','ERROR')", name='ck_segmentation_outcome'),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey('segmentation_rules.id'), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    outcome: Mapped[str] = mapped_column(String(30))
    expected: Mapped[dict[str, Any]] = mapped_column(JSON)
    observed: Mapped[dict[str, Any]] = mapped_column(JSON)
