"""scanner framework

Revision ID: 20260927_0004
Revises: 20260927_0003
Create Date: 2026-09-27 17:45:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260927_0004"
down_revision: Union[str, None] = "20260927_0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

scanner_job_status = postgresql.ENUM(
    "PREPARED",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    name="scanner_job_status",
    create_type=False,
)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE scanner_job_status AS ENUM ('PREPARED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END
        $$;
        """
    )

    op.create_table(
        "scanner_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("scope_id", sa.Integer(), nullable=False),
        sa.Column("adapter_name", sa.String(length=80), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("status", scanner_job_status, nullable=False),
        sa.Column("prepared_config", sa.JSON(), nullable=False),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("normalized_result", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scope_id"], ["scopes.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scanner_jobs_adapter_name"), "scanner_jobs", ["adapter_name"], unique=False)
    op.create_index(op.f("ix_scanner_jobs_organization_id"), "scanner_jobs", ["organization_id"], unique=False)
    op.create_index(op.f("ix_scanner_jobs_scope_id"), "scanner_jobs", ["scope_id"], unique=False)
    op.create_index(op.f("ix_scanner_jobs_target"), "scanner_jobs", ["target"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scanner_jobs_target"), table_name="scanner_jobs")
    op.drop_index(op.f("ix_scanner_jobs_scope_id"), table_name="scanner_jobs")
    op.drop_index(op.f("ix_scanner_jobs_organization_id"), table_name="scanner_jobs")
    op.drop_index(op.f("ix_scanner_jobs_adapter_name"), table_name="scanner_jobs")
    op.drop_table("scanner_jobs")
    op.execute("DROP TYPE IF EXISTS scanner_job_status")

