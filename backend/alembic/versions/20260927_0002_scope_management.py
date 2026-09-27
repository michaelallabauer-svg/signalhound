"""scope management

Revision ID: 20260927_0002
Revises: 20260927_0001
Create Date: 2026-09-27 16:50:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260927_0002"
down_revision: Union[str, None] = "20260927_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

scope_target_type = postgresql.ENUM(
    "DOMAIN",
    "HOSTNAME",
    "IP",
    "CIDR",
    name="scope_target_type",
    create_type=False,
)
scan_zone = postgresql.ENUM("EXTERNAL", name="scan_zone", create_type=False)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE scope_target_type AS ENUM ('DOMAIN', 'HOSTNAME', 'IP', 'CIDR');
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
            CREATE TYPE scan_zone AS ENUM ('EXTERNAL');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END
        $$;
        """
    )

    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_organizations_name"), "organizations", ["name"], unique=True)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("affected_object_type", sa.String(length=120), nullable=False),
        sa.Column("affected_object_id", sa.String(length=120), nullable=True),
        sa.Column("result", sa.String(length=80), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"], unique=False)

    op.create_table(
        "scopes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("target_type", scope_target_type, nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("scan_zone", scan_zone, nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "target_type",
            "target",
            "scan_zone",
            name="uq_scopes_org_target_zone",
        ),
    )
    op.create_index(op.f("ix_scopes_organization_id"), "scopes", ["organization_id"], unique=False)
    op.create_index(op.f("ix_scopes_target"), "scopes", ["target"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scopes_target"), table_name="scopes")
    op.drop_index(op.f("ix_scopes_organization_id"), table_name="scopes")
    op.drop_table("scopes")
    op.drop_index(op.f("ix_audit_logs_action"), table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index(op.f("ix_organizations_name"), table_name="organizations")
    op.drop_table("organizations")
    op.execute("DROP TYPE IF EXISTS scan_zone")
    op.execute("DROP TYPE IF EXISTS scope_target_type")
