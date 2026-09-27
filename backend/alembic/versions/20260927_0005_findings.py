"""findings

Revision ID: 20260927_0005
Revises: 20260927_0004
Create Date: 2026-09-27 18:20:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260927_0005"
down_revision: Union[str, None] = "20260927_0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

finding_severity = postgresql.ENUM("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="finding_severity", create_type=False)
finding_status = postgresql.ENUM(
    "NEW",
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "RESOLVED",
    "ACCEPTED_RISK",
    "FALSE_POSITIVE",
    name="finding_status",
    create_type=False,
)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE finding_severity AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END
        $$;
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE finding_status AS ENUM ('NEW', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END
        $$;
        """
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", finding_severity, nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("external_reference", sa.String(length=255), nullable=True),
        sa.Column("status", finding_status, nullable=False),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "asset_id",
            "service_id",
            "source",
            "external_reference",
            "title",
            name="uq_findings_identity",
        ),
    )
    op.create_index(op.f("ix_findings_asset_id"), "findings", ["asset_id"], unique=False)
    op.create_index(op.f("ix_findings_external_reference"), "findings", ["external_reference"], unique=False)
    op.create_index(op.f("ix_findings_organization_id"), "findings", ["organization_id"], unique=False)
    op.create_index(op.f("ix_findings_service_id"), "findings", ["service_id"], unique=False)
    op.create_index(op.f("ix_findings_source"), "findings", ["source"], unique=False)

    op.create_table(
        "finding_observations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_finding_observations_finding_id"), "finding_observations", ["finding_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_observations_finding_id"), table_name="finding_observations")
    op.drop_table("finding_observations")
    op.drop_index(op.f("ix_findings_source"), table_name="findings")
    op.drop_index(op.f("ix_findings_service_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_organization_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_external_reference"), table_name="findings")
    op.drop_index(op.f("ix_findings_asset_id"), table_name="findings")
    op.drop_table("findings")
    op.execute("DROP TYPE IF EXISTS finding_status")
    op.execute("DROP TYPE IF EXISTS finding_severity")

