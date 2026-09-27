"""asset inventory

Revision ID: 20260927_0003
Revises: 20260927_0002
Create Date: 2026-09-27 17:20:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260927_0003"
down_revision: Union[str, None] = "20260927_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

asset_type = postgresql.ENUM("DOMAIN", "SUBDOMAIN", "IP", "HOST", name="asset_type", create_type=False)
service_protocol = postgresql.ENUM("TCP", "UDP", name="service_protocol", create_type=False)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE asset_type AS ENUM ('DOMAIN', 'SUBDOMAIN', 'IP', 'HOST');
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
            CREATE TYPE service_protocol AS ENUM ('TCP', 'UDP');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END
        $$;
        """
    )

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("scope_id", sa.Integer(), nullable=True),
        sa.Column("asset_type", asset_type, nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("known_asset", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scope_id"], ["scopes.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "asset_type", "value", name="uq_assets_org_type_value"),
    )
    op.create_index(op.f("ix_assets_organization_id"), "assets", ["organization_id"], unique=False)
    op.create_index(op.f("ix_assets_scope_id"), "assets", ["scope_id"], unique=False)
    op.create_index(op.f("ix_assets_value"), "assets", ["value"], unique=False)

    op.create_table(
        "asset_observations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_asset_observations_asset_id"), "asset_observations", ["asset_id"], unique=False)

    op.create_table(
        "services",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("protocol", service_protocol, nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=True),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "protocol", "port", name="uq_services_asset_protocol_port"),
    )
    op.create_index(op.f("ix_services_asset_id"), "services", ["asset_id"], unique=False)

    op.create_table(
        "service_observations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_service_observations_service_id"), "service_observations", ["service_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_service_observations_service_id"), table_name="service_observations")
    op.drop_table("service_observations")
    op.drop_index(op.f("ix_services_asset_id"), table_name="services")
    op.drop_table("services")
    op.drop_index(op.f("ix_asset_observations_asset_id"), table_name="asset_observations")
    op.drop_table("asset_observations")
    op.drop_index(op.f("ix_assets_value"), table_name="assets")
    op.drop_index(op.f("ix_assets_scope_id"), table_name="assets")
    op.drop_index(op.f("ix_assets_organization_id"), table_name="assets")
    op.drop_table("assets")
    op.execute("DROP TYPE IF EXISTS service_protocol")
    op.execute("DROP TYPE IF EXISTS asset_type")

