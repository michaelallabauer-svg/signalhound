import enum
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


class ChangeEntityType(str, enum.Enum):
    ASSET = "ASSET"
    SERVICE = "SERVICE"
    FINDING = "FINDING"


class ChangeType(str, enum.Enum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"


class ChangeSet(Base):
    __tablename__ = "change_sets"

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    baseline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    comparison_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    events: Mapped[list["ChangeEvent"]] = relationship(back_populates="change_set")


class ChangeEvent(Base):
    __tablename__ = "change_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    change_set_id: Mapped[int] = mapped_column(
        ForeignKey("change_sets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_type: Mapped[ChangeEntityType] = mapped_column(
        Enum(ChangeEntityType, name="change_entity_type"),
        nullable=False,
    )
    change_type: Mapped[ChangeType] = mapped_column(Enum(ChangeType, name="change_type"), nullable=False)
    entity_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    object_id: Mapped[int | None] = mapped_column(nullable=True)
    before: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    change_set: Mapped[ChangeSet] = relationship(back_populates="events")
