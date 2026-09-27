"""change detection

Revision ID: 20260927_0006
Revises: 20260927_0005
Create Date: 2026-09-27 19:40:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260927_0006"
down_revision: Union[str, None] = "20260927_0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

change_entity_type = postgresql.ENUM("ASSET", "SERVICE", "FINDING", name="change_entity_type", create_type=False)
change_type = postgresql.ENUM("ADDED", "REMOVED", name="change_type", create_type=False)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE change_entity_type AS ENUM ('ASSET', 'SERVICE', 'FINDING');
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
            CREATE TYPE change_type AS ENUM ('ADDED', 'REMOVED');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END
        $$;
        """
    )

    op.create_table(
        "change_sets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("comparison_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_change_sets_organization_id"), "change_sets", ["organization_id"], unique=False)

    op.create_table(
        "change_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("change_set_id", sa.Integer(), nullable=False),
        sa.Column("entity_type", change_entity_type, nullable=False),
        sa.Column("change_type", change_type, nullable=False),
        sa.Column("entity_key", sa.String(length=512), nullable=False),
        sa.Column("object_id", sa.Integer(), nullable=True),
        sa.Column("before", sa.JSON(), nullable=True),
        sa.Column("after", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["change_set_id"], ["change_sets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_change_events_change_set_id"), "change_events", ["change_set_id"], unique=False)
    op.create_index(op.f("ix_change_events_entity_key"), "change_events", ["entity_key"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_change_events_entity_key"), table_name="change_events")
    op.drop_index(op.f("ix_change_events_change_set_id"), table_name="change_events")
    op.drop_table("change_events")
    op.drop_index(op.f("ix_change_sets_organization_id"), table_name="change_sets")
    op.drop_table("change_sets")
    op.execute("DROP TYPE IF EXISTS change_type")
    op.execute("DROP TYPE IF EXISTS change_entity_type")
