import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models import Base


class ScopeTargetType(str, enum.Enum):
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    IP = "IP"
    CIDR = "CIDR"


class ScanZone(str, enum.Enum):
    EXTERNAL = "EXTERNAL"
    INTERNAL_IT = "INTERNAL_IT"


class Scope(Base):
    __tablename__ = "scopes"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "target_type",
            "target",
            "scan_zone",
            name="uq_scopes_org_target_zone",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[ScopeTargetType] = mapped_column(
        Enum(ScopeTargetType, name="scope_target_type"),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scan_zone: Mapped[ScanZone] = mapped_column(
        Enum(ScanZone, name="scan_zone"),
        default=ScanZone.EXTERNAL,
        nullable=False,
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    organization: Mapped["Organization"] = relationship(back_populates="scopes")
