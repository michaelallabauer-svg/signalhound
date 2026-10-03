from datetime import datetime
from typing import Any
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column
from app.models import Base


class ScannerNode(Base):
    __tablename__ = 'scanner_nodes'
    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey('organizations.id'), index=True)
    name: Mapped[str] = mapped_column(String(160))
    bind_ip: Mapped[str] = mapped_column(String(45))
    target_scope_ids: Mapped[list[int]] = mapped_column(JSON)
    target_networks: Mapped[dict[str, str]] = mapped_column(JSON)
    allowed_ports: Mapped[list[int]] = mapped_column(JSON)
    capabilities: Mapped[list[str]] = mapped_column(JSON)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    credential_generation: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[str | None] = mapped_column(String(40))
    reported_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    execution_enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class NodeJob(Base):
    __tablename__ = 'node_jobs'
    __table_args__ = (CheckConstraint("status IN ('QUEUED','LEASED','RUNNING','COMPLETED','CANCELLED','EXPIRED')", name='ck_node_job_status'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey('scanner_nodes.id'), index=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey('segmentation_rules.id'), index=True)
    status: Mapped[str] = mapped_column(String(20))
    expected: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_hash: Mapped[str | None] = mapped_column(String(64))
    check_id: Mapped[int | None] = mapped_column(ForeignKey('segmentation_checks.id'), unique=True)
    result_hash: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(String(400))
